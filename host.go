// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements the host side of CGI (being the webserver
// parent process).

// Package cgi implements CGI (Common Gateway Interface) as specified
// in RFC 3875.
//
// Note that using CGI means starting a new process to handle each
// request, which is typically less efficient than using a
// long-running server. This package is intended primarily for
// compatibility with existing systems.
package fcgi

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var trailingPort = regexp.MustCompile(`:([0-9]+)$`)

var osDefaultInheritEnv = map[string][]string{
	"darwin":  {"DYLD_LIBRARY_PATH"},
	"freebsd": {"LD_LIBRARY_PATH"},
	"hpux":    {"LD_LIBRARY_PATH", "SHLIB_PATH"},
	"irix":    {"LD_LIBRARY_PATH", "LD_LIBRARYN32_PATH", "LD_LIBRARY64_PATH"},
	"linux":   {"LD_LIBRARY_PATH"},
	"openbsd": {"LD_LIBRARY_PATH"},
	"solaris": {"LD_LIBRARY_PATH", "LD_LIBRARY_PATH_32", "LD_LIBRARY_PATH_64"},
	"windows": {"SystemRoot", "COMSPEC", "PATHEXT", "WINDIR"},
}

// Handler runs an executable in a subprocess with a CGI environment.
type Handler struct {
	Path string // path to the CGI executable
	Root string // root URI prefix of handler or empty for "/"

	// Dir specifies the CGI executable's working directory.
	// If Dir is empty, the base directory of Path is used.
	// If Path has no base directory, the current working
	// directory is used.
	Dir string

	Env        []string    // extra environment variables to set, if any, as "key=value"
	InheritEnv []string    // environment variables to inherit from host, as "key"
	Logger     *log.Logger // optional log for errors or nil to use log.Print
	Args       []string    // optional arguments to pass to child process
	Stderr     io.Writer   // optional stderr for the child process; nil means os.Stderr

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

// removeLeadingDuplicates remove leading duplicate in environments.
// It's possible to override environment like following.
//    cgi.Handler{
//      ...
//      Env: []string{"SCRIPT_FILENAME=foo.php"},
//    }
func removeLeadingDuplicates(env []string) (ret []string) {
	for i, e := range env {
		found := false
		if eq := strings.IndexByte(e, '='); eq != -1 {
			keq := e[:eq+1] // "key="
			for _, e2 := range env[i+1:] {
				if strings.HasPrefix(e2, keq) {
					found = true
					break
				}
			}
		}
		if !found {
			ret = append(ret, e)
		}
	}
	return
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

	envPath := os.Getenv("PATH")
	if envPath == "" {
		envPath = "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
	}
	env = append(env, "PATH="+envPath)

	for _, e := range h.InheritEnv {
		if v := os.Getenv(e); v != "" {
			env = append(env, e+"="+v)
		}
	}

	for _, e := range osDefaultInheritEnv[runtime.GOOS] {
		if v := os.Getenv(e); v != "" {
			env = append(env, e+"="+v)
		}
	}

	if h.Env != nil {
		env = append(env, h.Env...)
	}

	env = removeLeadingDuplicates(env)

	var cwd, path string
	if h.Dir != "" {
		path = h.Path
		cwd = h.Dir
	} else {
		cwd, path = filepath.Split(h.Path)
	}
	if cwd == "" {
		cwd = "."
	}

	internalError := func(err error) {
		rw.WriteHeader(http.StatusInternalServerError)
		h.printf("CGI error: %v", err)
	}

	cmd := &exec.Cmd{
		Path:   path,
		Args:   append([]string{h.Path}, h.Args...),
		Dir:    cwd,
		Env:    env,
		Stderr: h.stderr(),
	}
	if req.ContentLength != 0 {
		cmd.Stdin = req.Body
	}
	stdoutRead, err := cmd.StdoutPipe()
	if err != nil {
		internalError(err)
		return
	}

	err = cmd.Start()
	if err != nil {
		internalError(err)
		return
	}
	if hook := testHookStartProcess; hook != nil {
		hook(cmd.Process)
	}
	defer cmd.Wait()
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
		// And kill the child CGI process so we don't hang on
		// the deferred cmd.Wait above if the error was just
		// the client (rw) going away. If it was a read error
		// (because the child died itself), then the extra
		// kill of an already-dead process is harmless (the PID
		// won't be reused until the Wait above).
		cmd.Process.Kill()
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

var testHookStartProcess func(*os.Process) // nil except for some tests

type host struct {
	conn      *conn
	stderr    io.Writer
	reqId     uint16
	out       []byte
	outClosed bool  // whether empty frame for out received
	ended     bool  // whether typeEndRequest has been received or there was a fcgi-level failure
	err       error // non-nil when a fcgi-level failure occurred
}

// handle issues an http request with cgi-style env headers and req body,
// returning HTTP-encoded response.
func (h *host) handle(env map[string]string, req io.Reader) error {
	if h.reqId == 0 {
		panic("reqId must be non-zero")
	}
	// Reset state for reuse
	h.out = nil
	h.outClosed = false
	h.ended = false
	h.err = nil

	if err := h.conn.writeBeginRequest(h.reqId, roleResponder, flagKeepConn); err != nil {
		return err
	}

	if err := h.conn.writePairs(typeParams, h.reqId, env); err != nil {
		return err
	}

	body := newWriter(h.conn, typeStdin, h.reqId)
	if req != nil {
		if _, err := io.Copy(body, req); err != nil {
			return err
		}
	}
	if err := body.Close(); err != nil {
		return err
	}

	return nil
}

func (h *host) stdoutPipe() io.ReadCloser {
	return &stdoutReader{h}
}

func (h *host) readAndProcess() error {
	var rec record
	if err := rec.read(h.conn.rwc); err != nil {
		return err
	}
	if err := h.handleRecord(&rec); err != nil {
		h.err = err
		h.ended = true
		return err
	}
	return nil
}

func (h *host) handleRecord(rec *record) error {
	if rec.h.Id == 0 {
		// management record
		// We won't receive typeGetValuesResult since we don't send typeGetValues
		// TODO: log for typeUnknownType?
		return nil
	}
	if rec.h.Id != h.reqId {
		// Applications must ignore unknown requestIds, but web servers don't
		return errors.New("fcgi: received frame for unexpected requestId")
	}

	switch rec.h.Type {
	case typeStdout:
		content := rec.content()
		if len(content) == 0 {
			// End of stream
			h.outClosed = true
		} else {
			h.out = append(h.out, content...)
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
		if h.ended {
			return errors.New("fcgi: received END_REQUEST for already-ended request")
		}
		h.ended = true
		var er endRequest
		if err := er.read(rec.content()); err != nil {
			return err
		}
		if er.protocolStatus != statusRequestComplete {
			// TODO: translate int to name
			return fmt.Errorf("fcgi: protocol status: %d", er.protocolStatus)
		}
		if er.appStatus != 0 {
			return fmt.Errorf("fcgi: application exit code: %d", er.appStatus)
		}
		if !h.outClosed {
			return errors.New("fcgi: request completed before stdout ended")
		}
		return nil
	default:
		// Applications have a graceful way to report unknown frame types, but web servers don't
		return fmt.Errorf("fcgi: received unknown frame type: %d", rec.h.Type)
	}
}

func (h *host) kill() error {
	if h.ended {
		return nil
	}
	if err := h.conn.writeAbortRequest(h.reqId); err != nil {
		return err
	}
	return nil
}

func (h *host) wait() error {
	for !h.ended {
		h.readAndProcess()
		h.out = nil
	}
	return h.err
}

type stdoutReader struct {
	h *host
}

func (r *stdoutReader) Read(p []byte) (n int, err error) {
	for {
		if len(r.h.out) > 0 {
			n = copy(p, r.h.out)
			r.h.out = r.h.out[n:]
			return
		}
		if r.h.outClosed {
			return 0, io.EOF
		}
		if r.h.err != nil {
			return 0, r.h.err
		}
		r.h.readAndProcess()
	}
}

func (r *stdoutReader) Close() error {
	if r.h.outClosed {
		return nil
	}
	if r.h.err != nil {
		return r.h.err
	}
	if err := r.h.conn.writeAbortRequest(r.h.reqId); err != nil {
		return err
	}
	return nil
}
