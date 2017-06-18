// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements the host side of FastCGI (being the webserver
// that connects as a client).

package fcgi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
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

	client, err := h.Dialer.Dial(req.Context())
	if err != nil {
		internalError(err)
		return
	}
	defer h.Dialer.Close(client)

	hostReq := &hostRequest{
		host:   &client.host,
		stderr: h.stderr(),
	}
	client.host.reserveReqId(hostReq)
	stdoutRead := hostReq.stdoutPipe()
	var body io.ReadCloser
	if req.ContentLength != 0 {
		body = req.Body
	}
	err = hostReq.handle(envSliceToMap(env), body)
	if err != nil {
		internalError(err)
		return
	}

	defer stdoutRead.Close()

	linebody := bufio.NewReaderSize(stdoutRead, 1024)
	headers := make(http.Header)
	statusCode := 0
	headerLines := 0
	sawBlankLine := false
	for {
		line, isPrefix, err := linebody.ReadLine()
		if isPrefix {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("cgi: long header line from subprocess.")
			return
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			h.printf("cgi: error reading headers: %v", err)
			return
		}
		if len(line) == 0 {
			sawBlankLine = true
			break
		}
		headerLines++
		parts := strings.SplitN(string(line), ":", 2)
		if len(parts) < 2 {
			h.printf("cgi: bogus header line: %s", string(line))
			continue
		}
		header, val := parts[0], parts[1]
		header = strings.TrimSpace(header)
		val = strings.TrimSpace(val)
		switch {
		case header == "Status":
			if len(val) < 3 {
				h.printf("cgi: bogus status (short): %q", val)
				return
			}
			code, err := strconv.Atoi(val[0:3])
			if err != nil {
				h.printf("cgi: bogus status: %q", val)
				h.printf("cgi: line was %q", line)
				return
			}
			statusCode = code
		default:
			headers.Add(header, val)
		}
	}
	if headerLines == 0 || !sawBlankLine {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("cgi: no headers")
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
		h.printf("cgi: missing required Content-Type in headers")
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
		h.printf("cgi: copy error: %v", err)
	}
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
		h.printf("cgi: error resolving local URI path %q: %v", path, err)
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

// envSliceToMap converts env slice to map. In case of duplicates, last instance wins.
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

// Dialer provides a Client when needed, allowing for reuse.
type Dialer interface {
	// Dial returns a Client for use, or error if unable
	Dial(ctx context.Context) (*Client, error)
	// Close returns the Client, where it may be closed
	Close(client *Client)
}

// BasicDialer simply creates a new Client each time
type BasicDialer struct {
	Network string
	Address string
}

func (d *BasicDialer) Dial(ctx context.Context) (*Client, error) {
	netDialer := net.Dialer{}
	netConn, err := netDialer.DialContext(ctx, d.Network, d.Address)
	if err != nil {
		return nil, err
	}
	return NewClient(netConn)
}

func (d *BasicDialer) Close(client *Client) {
	client.Close()
}

// Client is a connection to a FastCGI server, as used by a web server. It can
// support multiple concurrent requests, although using separate connections is
// encouraged as a slowly-drained response may slow all responses from the
// Client.
type Client struct {
	host host
}

// Close aborts any in-progress requests and frees the Client's resources
func (c *Client) Close() error {
	return c.host.shutdown()
}

// Returns non-nil when the Client is in a failing state and should no longer
// be used. Even with an error, Close is expected to be called eventually.
func (c *Client) Err() error {
	return c.host.err()
}

// NewClient creates a new client using netConn for communication. netConn must
// support multiple goroutines invoking its methods simultaneously.
func NewClient(netConn io.ReadWriteCloser) (*Client, error) {
	c := &Client{
		host{
			conn:          newConn(netConn),
			handshakeChan: make(chan struct{}),
			maxReqs:       math.MaxUint16,
			reqs:          make(map[uint16]*hostRequest),
		},
	}
	h := &c.host
	h.reqIdCond.L = &h.mutex
	go h.readLoop()

	values := map[string]string{
		"FCGI_MAX_REQS ":  "",
		"FCGI_MPXS_CONNS": "",
	}
	if err := h.conn.writeGetValues(values); err != nil {
		h.conn.Close()
		return nil, err
	}
	<-h.handshakeChan

	return c, nil
}

// host manages web server state for a fcgi connection. Senders write directly
// to the conn. It has a dedicated read goroutine, but it blocks waiting for
// readers to consume since fcgi lacks per-request flow control.
type host struct {
	conn *conn
	// handshakeChan is closed when handshake is complete.
	handshakeChan chan struct{}

	// mutex should be held when accessing the following fields.
	mutex sync.Mutex
	// handshaked is true when handshake is complete, to avoid closing
	// handshakeChan multiple times.
	handshaked bool
	// reqIdCond for coordinating when new reqIds may be available, or closed.
	reqIdCond sync.Cond
	// maxReqs is the maximum number of requests the fcgi application
	// supports. reqIdCond should be signaled when increased.
	maxReqs uint16
	// lastReqId is the last request id that has been used.
	lastReqId uint16
	// freeReqIds are request ids available for reuse. reqIdCond should be
	// signaled when added to.
	freeReqIds []uint16
	// reqs contains all requests still using their request id.
	reqs map[uint16]*hostRequest
	// closed is non-nil when communication is broken, to report via Err().
	// reqIdCond should be signaled when assigning.
	closed error
}

func (h *host) shutdown() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.closed != nil {
		return nil
	}
	h.closed = errors.New("fcgi: client closed")
	h.reqIdCond.Broadcast()
	for _, hr := range h.reqs {
		hr.tryClose(h.closed)
	}
	// This will cause reader goroutine to stop
	return h.conn.Close()
}

func (h *host) err() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.closed
}

func (h *host) readLoop() {
	// record is really large; it's important to only have one
	var rec record
	var err error
	for {
		if err = rec.read(h.conn.rwc); err != nil {
			break
		}
		if err = h.handleRecord(&rec); err != nil {
			break
		}
	}

	h.mutex.Lock()
	if !h.handshaked {
		h.handshaked = true
		close(h.handshakeChan)
	}
	if h.closed == nil {
		h.closed = err
		h.reqIdCond.Broadcast()
	}
	reqs := h.reqs
	h.reqs = nil
	h.mutex.Unlock()

	for _, hr := range reqs {
		hr.tryClose(err)
	}
}

// handleRecord returns an error for unrecoverable failures.
func (h *host) handleRecord(rec *record) error {
	if rec.h.Id == 0 {
		// management record
		switch rec.h.Type {
		case typeGetValuesResult:
			// Although this record is discrete, many
			// implementations (including Go's child) write it as
			// if it were a stream record. That mainly means being
			// able to handle an unrequested and empty
			// typeGetValuesResult.
			h.mutex.Lock()
			if !h.handshaked {
				h.handshaked = true
				close(h.handshakeChan)
			}
			values := readPairs(rec.content())
			if v, ok := intFromMap(values, "FCGI_MAX_REQS"); ok && uint16(v) > 1 {
				h.maxReqs = uint16(v)
				h.reqIdCond.Broadcast()
			}
			if v, ok := intFromMap(values, "FCGI_MPXS_CONNS"); ok {
				if v == 0 {
					h.maxReqs = 1
				}
			}
			h.mutex.Unlock()
		default:
			// TODO: log for typeUnknownType?
		}
		return nil
	}
	h.mutex.Lock()
	hr, ok := h.reqs[rec.h.Id]
	h.mutex.Unlock()
	if !ok {
		// Applications must ignore unknown requestIds, but web servers don't
		return errors.New("fcgi: received frame for unexpected requestId")
	}

	return hr.handleRecord(rec)
}

func intFromMap(m map[string]string, k string) (i int, ok bool) {
	s, ok := m[k]
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return i, true
}

// reserveReqId allocates a request id, blocking as necessary. If the
// connection is failing, 0 is used.
func (h *host) reserveReqId(hr *hostRequest) {
	var reqId uint16
	h.mutex.Lock()
	defer h.mutex.Unlock()
	for {
		if h.closed != nil {
			hr.reqId = 0
			return
		}
		if len(h.freeReqIds) != 0 {
			reqId = h.freeReqIds[len(h.freeReqIds)-1]
			h.freeReqIds = h.freeReqIds[:len(h.freeReqIds)-1]
			break
		}
		if h.lastReqId < h.maxReqs {
			h.lastReqId += 1
			reqId = h.lastReqId
			break
		}
		h.reqIdCond.Wait()
	}
	hr.reqId = reqId
	h.reqs[reqId] = hr
}

// returnReqId returns reqId to a pool for reuse. It must be completely unused,
// including sending, receiving, and error handling.
func (h *host) returnReqId(reqId uint16) {
	h.mutex.Lock()
	if _, ok := h.reqs[reqId]; !ok {
		panic("request id not registered")
	}
	delete(h.reqs, reqId)
	h.freeReqIds = append(h.freeReqIds, reqId)
	h.reqIdCond.Signal()
	h.mutex.Unlock()
}

// hostRequest is a fcgi request as managed by the web server.
type hostRequest struct {
	// must be set before handle()
	host   *host
	stdout *io.PipeWriter
	stderr io.Writer
	reqId  uint16

	stdoutClose sync.Once // first close should win

	// state for reader
	stdoutEOS    bool // stdoutEOS is true after receiving empty frame for stdout
	abortedAsync bool // aborted is true if an async abort has already occurred

	// mutex should be held when accessing the following fields
	mutex           sync.Mutex
	inEnded         bool // inEnded is true after receiving typeEndRequest
	outEnded        bool // outEnded is true after closing stdout or sending abortRequest
	abortInProgress bool
}

func (hr *hostRequest) tryClose(err error) {
	hr.stdoutClose.Do(func() {
		hr.stdout.CloseWithError(err)
	})
}

// stdoutPipe initializes stdout with a pipe and returns the pipe's ReadCloser.
// The pipe is request-aware, so it can abort the request when appropriate.
func (hr *hostRequest) stdoutPipe() io.ReadCloser {
	var rc io.ReadCloser
	rc, hr.stdout = io.Pipe()
	return &abortReader{rc, hr}
}

// handle issues an http request with cgi-style env headers and req body,
// returning HTTP-encoded response. req will be consumed in a separate goroutine.
func (hr *hostRequest) handle(env map[string]string, req io.ReadCloser) error {
	if hr.reqId == 0 {
		// reserveReqId may have detected a failure
		if err := hr.host.err(); err != nil {
			return err
		}
		panic("reqId must be non-zero")
	}
	if hr.stdout == nil {
		panic("stdoutPipe must be called before handle")
	}
	if err := hr.host.conn.writeBeginRequest(hr.reqId, roleResponder, flagKeepConn); err != nil {
		return err
	}

	if err := hr.host.conn.writeParams(hr.reqId, env); err != nil {
		return err
	}

	outEnded := func() {
		hr.mutex.Lock()
		hr.outEnded = true
		allDone := hr.allDoneLocked()
		hr.mutex.Unlock()
		if allDone {
			hr.host.returnReqId(hr.reqId)
		}

	}
	if req == nil {
		body := newWriter(hr.host.conn, typeStdin, hr.reqId)
		if err := body.Close(); err != nil {
			return err
		}
		outEnded()
	} else {
		go func() {
			body := newWriter(hr.host.conn, typeStdin, hr.reqId)
			_, err := io.Copy(body, req)
			if err1 := req.Close(); err == nil {
				err = err1
			}
			if err == nil {
				err = body.Close()
			} else {
				hr.host.conn.writeAbortRequest(hr.reqId)
			}
			if err != nil {
				hr.tryClose(err)
			}
			outEnded()
		}()
	}

	return nil
}

// handleRecord returns an error for unrecoverable failures that impact the
// entire connection.
func (hr *hostRequest) handleRecord(rec *record) error {
	switch rec.h.Type {
	case typeStdout:
		content := rec.content()
		if len(content) == 0 {
			// End of stream
			hr.stdoutEOS = true
		} else {
			// This may take a long time
			if _, err := hr.stdout.Write(content); err != nil {
				if hr.abortedAsync {
					return nil
				}
				hr.abortedAsync = true
				// sending from read loop could cause deadlock.
				// If this turns out to be frequent, it could
				// be replaced with a dedicated goroutine that
				// receives abort requests from an unbounded
				// queue.
				go hr.abortReader()
			}
		}
		return nil
	case typeStderr:
		content := rec.content()
		if len(content) == 0 {
			// End of stream. Nothing really to do
		} else {
			// TODO: how to report error?
			hr.stderr.Write(content)
		}
		return nil
	case typeEndRequest:
		hr.mutex.Lock()
		hr.inEnded = true
		allDone := hr.allDoneLocked()
		hr.mutex.Unlock()
		if allDone {
			hr.host.returnReqId(hr.reqId)
		}

		var er endRequest
		if err := er.read(rec.content()); err != nil {
			return err
		}
		if er.protocolStatus != statusRequestComplete {
			// TODO: translate int to name
			hr.tryClose(
				fmt.Errorf("fcgi: protocol status: %d", er.protocolStatus))
			return nil
		}
		if er.appStatus != 0 {
			hr.tryClose(
				fmt.Errorf("fcgi: application exit code: %d", er.appStatus))
			return nil
		}
		if !hr.stdoutEOS {
			hr.tryClose(
				errors.New("fcgi: request completed before stdout ended"))
			return nil
		}
		hr.stdoutClose.Do(func() {
			hr.stdout.Close()
		})
		return nil
	default:
		// Applications have a graceful way to report unknown frame types, but web servers don't
		return fmt.Errorf("fcgi: received unknown frame type: %d", rec.h.Type)
	}
}

// allDoneLocked returns true if this request will no longer use its reqId.
// mutex must be held when calling this function.
func (hr *hostRequest) allDoneLocked() bool {
	// when changing this, audit needToAbort in abortReader.Close()
	return hr.inEnded && hr.outEnded && !hr.abortInProgress
}

func (hr *hostRequest) abortReader() error {
	hr.mutex.Lock()
	needToAbort := !hr.inEnded && hr.outEnded && !hr.abortInProgress
	hr.abortInProgress = needToAbort
	hr.mutex.Unlock()

	if !needToAbort {
		return nil
	}
	// outEnded is already true
	err := hr.host.conn.writeAbortRequest(hr.reqId)

	hr.mutex.Lock()
	hr.abortInProgress = false
	allDone := hr.allDoneLocked()
	hr.mutex.Unlock()
	if allDone {
		hr.host.returnReqId(hr.reqId)
	}
	return err
}

type abortReader struct {
	io.ReadCloser
	hr *hostRequest
}

func (r *abortReader) Close() error {
	r.ReadCloser.Close()
	return r.hr.abortReader()
}
