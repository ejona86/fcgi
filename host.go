// Copyright 2011 The Go Authors and Copyright 2017 Eric Anderson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fcgi

// This file implements the host side of FastCGI (being the webserver
// that connects as a client).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var trailingPort = regexp.MustCompile(`:([0-9]+)$`)

// Handler runs an executable in a subprocess with a CGI environment.
type Handler struct {
	Dialer Dialer // dialer for each request

	Path string // path to the CGI executable
	Root string // root URI prefix of handler or empty for "/"

	Env    []string    // extra environment variables to set, if any, as "key=value"
	Logger *log.Logger // optional log for errors or nil to use log.Print
	Stderr io.Writer   // optional stderr for the child process; nil means os.Stderr

	// PathLocationHandler specifies the root http Handler that
	// should handle internal redirects when the CGI process
	// returns a Location header value starting with a "/", as
	// specified in RFC 3875 § 6.3.2. This will likely be
	// http.DefaultServeMux.
	//
	// If nil, a CGI response with a local URI path is instead sent
	// back to the client and not redirected internally.
	PathLocationHandler http.Handler
}

func (h *Handler) stderr() io.Writer {
	if h.Stderr != nil {
		return h.Stderr
	}
	return os.Stderr
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Chunked request bodies are not supported by CGI."))
		return
	}

	pathInfo := req.URL.Path
	if root != "/" && strings.HasPrefix(pathInfo, root) {
		pathInfo = pathInfo[len(root):]
	}

	port := "80"
	if matches := trailingPort.FindStringSubmatch(req.Host); len(matches) != 0 {
		port = matches[1]
	}

	env := []string{
		"SERVER_SOFTWARE=go",
		"SERVER_NAME=" + req.Host,
		"SERVER_PROTOCOL=HTTP/1.1",
		"HTTP_HOST=" + req.Host,
		"GATEWAY_INTERFACE=CGI/1.1",
		"REQUEST_METHOD=" + req.Method,
		"QUERY_STRING=" + req.URL.RawQuery,
		"REQUEST_URI=" + req.URL.RequestURI(),
		"PATH_INFO=" + pathInfo,
		"SCRIPT_NAME=" + root,
		"SCRIPT_FILENAME=" + h.Path,
		"SERVER_PORT=" + port,
	}

	if remoteIP, remotePort, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		env = append(env, "REMOTE_ADDR="+remoteIP, "REMOTE_HOST="+remoteIP, "REMOTE_PORT="+remotePort)
	} else {
		// could not parse ip:port, let's use whole RemoteAddr and leave REMOTE_PORT undefined
		env = append(env, "REMOTE_ADDR="+req.RemoteAddr, "REMOTE_HOST="+req.RemoteAddr)
	}

	if req.TLS != nil {
		env = append(env, "HTTPS=on")
	}

	for k, v := range req.Header {
		k = strings.Map(upperCaseAndUnderscore, k)
		if k == "PROXY" {
			// See Issue 16405
			continue
		}
		joinStr := ", "
		if k == "COOKIE" {
			joinStr = "; "
		}
		env = append(env, "HTTP_"+k+"="+strings.Join(v, joinStr))
	}

	if req.ContentLength > 0 {
		env = append(env, fmt.Sprintf("CONTENT_LENGTH=%d", req.ContentLength))
	}
	if ctype := req.Header.Get("Content-Type"); ctype != "" {
		env = append(env, "CONTENT_TYPE="+ctype)
	}

	if h.Env != nil {
		env = append(env, h.Env...)
	}

	internalError := func(err error) {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("CGI error: %v", err)
	}

	var dialer poolableDialer
	if d, ok := h.Dialer.(poolableDialer); ok {
		dialer = d
	} else {
		dialer = poolableDialerAdapter{h.Dialer}
	}
	conn, err := h.Dialer.Dial(req.Context())
	if err != nil {
		internalError(err)
		return
	}
	if deadline, ok := req.Context().Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	// TODO: observe context.Done()?
	host := &host{
		conn:   newConn(conn),
		stderr: h.stderr(),
		rec:    recordPool.Get().(*record),
	}

	var body io.ReadCloser
	if req.ContentLength != 0 {
		body = req.Body
	}

	err = host.handle(envSliceToMap(env), body)
	if err != nil {
		internalError(err)
		conn.Close()
		return
	}
	var graceful bool
	defer func() {
		if graceful {
			// Gracefully wait for the request to end, then close the
			// connection. Report any errors
			err := host.wait()
			// FYI: If err == nul, at this point it would be safe to re-use the
			// connection and the reqId
			if err2 := dialer.put(conn); err != nil {
				err = err2
			}
			if err != nil {
				h.printf("fcgi: final error: %v", err)
			}
		} else {
			// Tear down as quickly as possible. Ignore any errors, since we've
			// already reported an error and this teardown will produce more.
			// Make sure Close() happens before wait() to guarantee wait() will return
			conn.Close()
			host.wait()
		}
	}()

	var stdoutRead io.Reader = host
	linebody := bufio.NewReaderSize(stdoutRead, 1024)
	headers := make(http.Header)
	statusCode := 0
	headerLines := 0
	sawBlankLine := false
	for {
		line, isPrefix, err := linebody.ReadLine()
		if isPrefix {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("fcgi: long header line from subprocess.")
			return
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("fcgi: error reading headers: %v", err)
			return
		}
		if len(line) == 0 {
			sawBlankLine = true
			break
		}
		headerLines++
		parts := strings.SplitN(string(line), ":", 2)
		if len(parts) < 2 {
			h.printf("fcgi: bogus header line: %s", string(line))
			continue
		}
		header, val := parts[0], parts[1]
		header = strings.TrimSpace(header)
		val = strings.TrimSpace(val)
		switch {
		case header == "Status":
			if len(val) < 3 {
				h.printf("fcgi: bogus status (short): %q", val)
				return
			}
			code, err := strconv.Atoi(val[0:3])
			if err != nil {
				h.printf("fcgi: bogus status: %q", val)
				h.printf("fcgi: line was %q", line)
				return
			}
			statusCode = code
		default:
			headers.Add(header, val)
		}
	}
	if headerLines == 0 || !sawBlankLine {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("fcgi: no headers")
		return
	}

	if loc := headers.Get("Location"); loc != "" {
		if strings.HasPrefix(loc, "/") && h.PathLocationHandler != nil {
			h.handleInternalRedirect(rw, req, loc)
			return
		}
		if statusCode == 0 {
			statusCode = http.StatusFound
		}
	}

	if statusCode == 0 && headers.Get("Content-Type") == "" {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("fcgi: missing required Content-Type in headers")
		return
	}

	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	// Copy headers to rw's headers, after we've decided not to
	// go into handleInternalRedirect, which won't want its rw
	// headers to have been touched.
	for k, vv := range headers {
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}

	rw.WriteHeader(statusCode)

	_, err = io.Copy(rw, linebody)
	if err != nil {
		h.printf("fcgi: copy error: %v", err)
		return
	}
	graceful = true
}

func (h *Handler) printf(format string, v ...interface{}) {
	if h.Logger != nil {
		h.Logger.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

func (h *Handler) handleInternalRedirect(rw http.ResponseWriter, req *http.Request, path string) {
	url, err := req.URL.Parse(path)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("fcgi: error resolving local URI path %q: %v", path, err)
		return
	}
	// TODO: RFC 3875 isn't clear if only GET is supported, but it
	// suggests so: "Note that any message-body attached to the
	// request (such as for a POST request) may not be available
	// to the resource that is the target of the redirect."  We
	// should do some tests against Apache to see how it handles
	// POST, HEAD, etc. Does the internal redirect get the same
	// method or just GET? What about incoming headers?
	// (e.g. Cookies) Which headers, if any, are copied into the
	// second request?
	newReq := &http.Request{
		Method:     "GET",
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       url.Host,
		RemoteAddr: req.RemoteAddr,
		TLS:        req.TLS,
	}
	h.PathLocationHandler.ServeHTTP(rw, newReq)
}

func upperCaseAndUnderscore(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return r - ('a' - 'A')
	case r == '-':
		return '_'
	case r == '=':
		// Maybe not part of the CGI 'spec' but would mess up
		// the environment in any case, as Go represents the
		// environment as a slice of "key=value" strings.
		return '_'
	}
	// TODO: other transformations in spec or practice?
	return r
}

// envSliceToMap converts env slice to map. In case of duplicates, last
// instance wins.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, e := range env {
		if eq := strings.IndexByte(e, '='); eq != -1 {
			key := e[:eq]
			value := e[eq+1:]
			m[key] = value
		}
	}
	return m
}

// Dialer creates a connection.
type Dialer interface {
	// Dial returns a connection for use, or error if unable
	Dial(ctx context.Context) (net.Conn, error)
}

// poolableDialer allows reusing net.Conns
type poolableDialer interface {
	Dialer
	// put returns conn, allowing it to be returned to a pool or closed
	put(conn net.Conn) error
}

type poolableDialerAdapter struct {
	Dialer
}

func (d poolableDialerAdapter) put(conn net.Conn) error {
	return conn.Close()
}

type NetDialer struct {
	Network string
	Address string
	// Dialer is the dialer configuration to use. nil implies default
	// configuration.
	Dialer *net.Dialer
}

func (d *NetDialer) Dial(ctx context.Context) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return dialer.DialContext(ctx, d.Network, d.Address)
}

const reqId = 1

var endedError error = errors.New("response complete; request implicitly closed")

var recordPool sync.Pool = sync.Pool{
	New: func() interface{} {
		return &record{}
	},
}

type host struct {
	conn   *conn
	stderr io.Writer
	rec    *record

	stdout       []byte
	stdoutClosed bool // whether empty frame for stdout received
	// protects req from being used after Handle returns
	writerDone sync.WaitGroup

	mu sync.Mutex
	// whether typeEndRequest has been received or there was a fcgi-level
	// failure. ended may only be modified on the stdout-reading goroutine. mu
	// must be held when modifying or reading outside of the stdout-reading
	// goroutine
	ended bool
	// mu must be held when reading or writing writerErr
	writerErr error
}

// handle issues an http request with cgi-style env headers and req body,
// returning HTTP-encoded response.
func (h *host) handle(env map[string]string, req io.ReadCloser) error {
	if err := h.conn.writeBeginRequest(reqId, roleResponder, flagKeepConn); err != nil {
		return err
	}

	if err := h.conn.writePairs(typeParams, reqId, env); err != nil {
		return err
	}

	if req == nil {
		if err := h.conn.writeRecord(typeStdin, reqId, nil); err != nil {
			return err
		}
	} else {
		// must send from separate goroutine to avoid deadlock. The
		// earlier writes were safe because there were no outstanding
		// requests (and so the fcgi server couldn't be blocked on a
		// write)
		h.writerDone.Add(1)
		go func() {
			defer h.writerDone.Done()
			body := &streamWriter{c: h.conn, recType: typeStdin, reqId: reqId}
			// Since ServeHTTP() can't return until this goroutine completes,
			// try to return promptly if the response completes early.
			_, err := io.Copy(body, checkEndedReader{req, h})
			if err == endedError {
				err = nil
			}
			if err1 := req.Close(); err == nil {
				err = err1
			}
			if err != nil {
				// Set writerErr before writeAbortRequest, so it is set for receiving typeEndRequest
				h.mu.Lock()
				h.writerErr = err
				h.mu.Unlock()
				// Squelch returned error; already reporting an error
				h.conn.writeAbortRequest(reqId)
				return
			}
			err = body.Close()
			if err != nil {
				h.mu.Lock()
				h.writerErr = err
				h.mu.Unlock()
			}
		}()
	}

	return nil
}

func (h *host) readAndProcess() error {
	if h.ended {
		panic("already ended")
	}
	if err := h.rec.read(h.conn.rwc); err != nil {
		h.mu.Lock()
		h.ended = true
		h.mu.Unlock()
		recordPool.Put(h.rec)
		h.rec = nil
		return err
	}
	if err := h.handleRecord(h.rec); err != nil {
		h.mu.Lock()
		h.ended = true
		h.mu.Unlock()
		recordPool.Put(h.rec)
		h.rec = nil
		return err
	}
	return nil
}

func (h *host) handleRecord(rec *record) error {
	if rec.h.Id == 0 {
		// management record
		// We shouldn't receive typeGetValuesResult since we don't send
		// typeGetValues
		return fmt.Errorf("fcgi: unexpected management record: %d", rec.h.Type)
	}
	if rec.h.Id != reqId {
		// Applications must ignore unknown requestIds, but web servers don't
		return errors.New("fcgi: received frame for unexpected requestId")
	}

	switch rec.h.Type {
	case typeStdout:
		content := rec.content()
		if len(content) == 0 {
			// End of stream
			h.stdoutClosed = true
		} else {
			if len(h.stdout) > 0 {
				panic("stdout not empty!")
			}
			h.stdout = content
		}
		return nil
	case typeStderr:
		content := rec.content()
		if len(content) == 0 {
			// End of stream. Nothing really to do
		} else {
			// TODO: how to report error?
			h.stderr.Write(content)
		}
		return nil
	case typeEndRequest:
		var er endRequest
		if err := er.read(rec.content()); err != nil {
			return err
		}
		h.mu.Lock()
		writerErr := h.writerErr
		h.mu.Unlock()
		if writerErr != nil {
			return writerErr
		}
		if er.protocolStatus != statusRequestComplete {
			if er.protocolStatus < uint8(len(statusName)) {
				return fmt.Errorf("fcgi: protocol status: %s", statusName[er.protocolStatus])
			} else {
				return fmt.Errorf("fcgi: protocol status: %d", er.protocolStatus)
			}
		}
		if er.appStatus != 0 {
			return fmt.Errorf("fcgi: application exit code: %d", er.appStatus)
		}
		if !h.stdoutClosed {
			// Request completed before stdout ended, which is against the
			// spec, but PHP does this... so let's just implicitly close
			h.stdoutClosed = true
		}

		// Set ended after any possible errors to avoid double-handling
		h.mu.Lock()
		h.ended = true
		h.mu.Unlock()
		recordPool.Put(h.rec)
		h.rec = nil

		return nil
	default:
		// Applications have a graceful way to report unknown frame types, but
		// web servers don't
		return fmt.Errorf("fcgi: received unknown frame type: %d", rec.h.Type)
	}
}

func (h *host) wait() error {
	var err error
	for !h.ended {
		err = h.readAndProcess()
		h.stdout = nil
	}
	h.writerDone.Wait()
	return err
}

func (h *host) Read(p []byte) (n int, err error) {
	for {
		if len(h.stdout) > 0 {
			n = copy(p, h.stdout)
			h.stdout = h.stdout[n:]
			return
		}
		if h.stdoutClosed {
			return 0, io.EOF
		}
		if err := h.readAndProcess(); err != nil {
			return 0, err
		}
	}
}

type checkEndedReader struct {
	io.ReadCloser
	h *host
}

func (r checkEndedReader) Read(p []byte) (int, error) {
	r.h.mu.Lock()
	stop := r.h.ended
	r.h.mu.Unlock()

	if stop {
		return 0, endedError
	}
	return r.ReadCloser.Read(p)
}
