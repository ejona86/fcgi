// Copyright 2017 Eric Anderson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fcgi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Buffered in one direction, unbuffered in the other. Only unbuffered
// direction is synchronized.
func testPipe() (bufWrite io.ReadWriteCloser, bufRead io.ReadWriteCloser) {
	r, w := io.Pipe()
	b := &bytes.Buffer{}
	return &struct {
			io.ReadCloser
			io.Writer
		}{r, b},
		&struct {
			io.WriteCloser
			io.Reader
		}{w, b}
}

type verifyReadCloser struct {
	io.Reader
	closed bool
}

func (r *verifyReadCloser) Close() error {
	r.closed = true
	return nil
}

func handle(
	h *host, bufRead io.Reader, env map[string]string, reqContent string,
) (m map[string]string, b string, err error) {
	var body io.ReadCloser
	if reqContent != "" {
		vrc := &verifyReadCloser{Reader: bytes.NewBufferString(reqContent)}
		defer func() {
			if !vrc.closed {
				err = fmt.Errorf("body not closed")
			}
		}()
		body = vrc
	}
	var rec record
	if err := h.handle(env, body); err != nil {
		return nil, "", fmt.Errorf("failed to write request: %v", err)
	}
	h.writerDone.Wait()

	// BeginRequest
	if err := rec.read(bufRead); err != nil {
		return nil, "", fmt.Errorf("couldn't get BeginRequest: %v", err)
	}
	if rec.h.Type != typeBeginRequest || rec.h.Id != 1 {
		return nil, "", fmt.Errorf("got %v instead of BeginRequest", rec.h)
	}
	br := &beginRequest{}
	if err := br.read(rec.content()); err != nil {
		return nil, "", fmt.Errorf("couldn't parse BeginRequest: %v", err)
	}
	goldenBr := &beginRequest{role: roleResponder, flags: flagKeepConn}
	if s, ok := equal(goldenBr, br); !ok {
		return nil, "", fmt.Errorf(s)
	}

	// Params
	var content []byte
	for {
		if err := rec.read(bufRead); err != nil {
			return nil, "", fmt.Errorf("couldn't get Params: %v", err)
		}
		if rec.h.Type != typeParams || rec.h.Id != 1 {
			return nil, "", fmt.Errorf("got %#v instead of Params", rec.h)
		}
		if len(rec.content()) == 0 {
			break
		}
		content = append(content, rec.content()...)
	}
	nvp := &nameValuePairs{}
	if err := nvp.read(content); err != nil {
		return nil, "", fmt.Errorf("couldn't parse Params: %v", err)
	}
	m = nvp.m

	// Stdin
	content = nil
	for {
		if err := rec.read(bufRead); err != nil {
			return m, string(content), fmt.Errorf("couldn't get Stdin: %v", err)
		}
		if rec.h.Type != typeStdin || rec.h.Id != 1 {
			return m, string(content), fmt.Errorf("got %v instead of Stdin", rec.h)
		}
		if len(rec.content()) == 0 {
			break
		}
		content = append(content, rec.content()...)
	}
	return m, string(content), nil
}

func TestHostNoBodyAndResponse(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	{
		m := map[string]string{"h1": "v1", "h2": "v2"}
		m2, c, err := handle(h, bufRead, m, "")
		if err != nil {
			t.Fatalf("handle failed: %v", err)
		}
		if s, ok := equal(m, m2); !ok {
			t.Fatalf("handle wrote wrong headers: %v", s)
		}
		if c != "" {
			t.Fatalf("got %s expected no content", c)
		}
	}

	var wg sync.WaitGroup
	response := "hello, world"
	wg.Add(1)
	go func() {
		defer wg.Done()
		stdout := newWriter(conn, typeStdout, 1)
		if _, err := stdout.WriteString(response); err != nil {
			t.Fatalf("Failed writing response: %v", err)
		}
		if err := stdout.Close(); err != nil {
			t.Fatalf("Failed closing stdout: %v", err)
		}
		if err := newWriter(conn, typeStderr, 1).Close(); err != nil {
			t.Fatalf("Failed closing stderr: %v", err)
		}
		if err := conn.writeEndRequest(1, 0, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err != nil {
		t.Fatalf("Failed to read stdin: %v", err)
	}
	if s, ok := equal(response, string(b.Bytes())); !ok {
		t.Fatalf("Wrong request content: %v", s)
	}
	if err := h.wait(); err != nil {
		t.Fatalf("Failed waiting: %v", err)
	}
	wg.Wait()
}

func TestHostBody(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}

	m := map[string]string{"h3": "v3"}
	c := "badger, badger"
	m2, c2, err := handle(h, bufRead, m, c)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	if s, ok := equal(m, m2); !ok {
		t.Fatalf("handle wrote wrong headers: %v", s)
	}
	if c != c2 {
		t.Fatalf("got %s expected %s", c2, c)
	}
}

func TestHostErrorBody(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	rpipe, wpipe := io.Pipe()
	goldenErr := errors.New("expected")
	wpipe.CloseWithError(goldenErr)

	vrc := &verifyReadCloser{Reader: rpipe}
	if err := h.handle(nil, vrc); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}
	h.writerDone.Wait()

	var rec record
	// BeginRequest
	if err := rec.read(bufRead); err != nil {
		t.Fatalf("couldn't get BeginRequest: %v", err)
	}
	if rec.h.Type != typeBeginRequest || rec.h.Id != 1 {
		t.Fatalf("got %v instead of BeginRequest", rec.h)
	}

	// Params
	for {
		if err := rec.read(bufRead); err != nil {
			t.Fatalf("couldn't get Params: %v", err)
		}
		if rec.h.Type != typeParams || rec.h.Id != 1 {
			t.Fatalf("got %v instead of Params", rec.h)
		}
		if len(rec.content()) == 0 {
			break
		}
	}

	// AbortRequest
	if err := rec.read(bufRead); err != nil {
		t.Fatalf("couldn't get AbortRequest: %v", err)
	}
	if rec.h.Type != typeAbortRequest || rec.h.Id != 1 {
		t.Fatalf("got %v instead of AbortRequest", rec.h)
	}

	// Response
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		appStatus := 1 // a failure
		if err := conn.writeEndRequest(1, appStatus, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	if err := h.wait(); err == nil || err != goldenErr {
		t.Fatalf("in handleReader: got %v expected %v", err, goldenErr)
	}
	if !vrc.closed {
		t.Fatalf("body not closed")
	}
}

func newDelayedReader() *delayedReader {
	return &delayedReader{make(chan struct{})}
}

// delayedReader blocks Read() until permitReads() is called, and then always
// reads a single zero byte.
type delayedReader struct {
	c chan struct{}
}

func (d *delayedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	<-d.c
	p[0] = 0
	return 1, nil
}

func (d *delayedReader) permitReads() {
	close(d.c)
}

func TestHostEarlyResponse(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	// It'd be okay if Read() returned before permitReads(), but we want to
	// avoid the writer goroutine from spinning on the never-ending reads. This
	// is better than a sleep before each read.
	delayedReader := newDelayedReader()
	vrc := &verifyReadCloser{Reader: delayedReader}
	if err := h.handle(nil, vrc); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	// Response
	var wg sync.WaitGroup
	response := "quick draw mcgraw"
	wg.Add(1)
	go func() {
		defer wg.Done()

		stdout := newWriter(conn, typeStdout, 1)
		if _, err := stdout.WriteString(response); err != nil {
			t.Fatalf("Failed writing response: %v", err)
		}
		if err := stdout.Close(); err != nil {
			t.Fatalf("Failed closing stdout: %v", err)
		}
		if err := newWriter(conn, typeStderr, 1).Close(); err != nil {
			t.Fatalf("Failed closing stderr: %v", err)
		}
		// App did not fail; it just returned early
		if err := conn.writeEndRequest(1, 0, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}

		// Spin until h.wait() has noticed the EndRequest. This also is to
		// avoid spinning on Read()
		for ended := false; !ended; {
			runtime.Gosched()
			h.mu.Lock()
			ended = h.ended
			h.mu.Unlock()
		}
		delayedReader.permitReads()
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err != nil {
		t.Fatalf("failed reading stdout: %s", err)
	}
	actualResponse := string(b.Bytes())
	if response != actualResponse {
		t.Fatalf("response mismatch: got %s expected %s", actualResponse, response)
	}
	if err := h.wait(); err != nil {
		t.Fatalf("wait failed: %s", err)
	}
	wg.Wait()
	if !vrc.closed {
		t.Fatalf("body not closed")
	}
}

func TestHostEarlyProtocolStatus(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.writeEndRequest(1, 0, statusOverloaded); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	if err := h.wait(); err == nil || !strings.Contains(err.Error(), "FCGI_OVERLOADED") {
		t.Fatalf("Error did not contain FCGI_OVERLOADED: %v", err)
	}
	wg.Wait()
}

func TestHostUnknownProtocolStatus(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.writeEndRequest(1, 0, 99); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	if err := h.wait(); err == nil || !strings.Contains(err.Error(), "99") ||
		!strings.Contains(err.Error(), "protocol status") {
		t.Fatalf("Error did not contain 99 or protocol status: %v", err)
	}
	wg.Wait()
}

func TestHostBadStatusAfterStdout(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := newWriter(conn, typeStdout, 1).Close(); err != nil {
			t.Fatalf("Failed closing stdout: %v", err)
		}
		if err := newWriter(conn, typeStderr, 1).Close(); err != nil {
			t.Fatalf("Failed closing stderr: %v", err)
		}
		if err := conn.writeEndRequest(1, 314, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	if err := h.wait(); err == nil || !strings.Contains(err.Error(), "314") {
		t.Fatalf("Error did not contain 314: %v", err)
	}
	wg.Wait()
}

func TestHostIgnorePhpOpenStdout(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// PHP doesn't terminate stdout
		if err := conn.writeEndRequest(1, 0, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	if err := h.wait(); err != nil {
		t.Fatalf("Failed waiting: %v", err)
	}
	wg.Wait()
}

func TestHostStderr(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	errOut := &bytes.Buffer{}
	// We are lazy in other tests and don't initialize stderr. However, outside
	// of tests it is always initialized
	h := &host{
		conn:   newConn(bufWrite),
		stderr: errOut,
		rec:    &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	response := "the good"
	errResponse := "the bad"
	wg.Add(1)
	go func() {
		defer wg.Done()
		stderr := newWriter(conn, typeStderr, 1)
		if _, err := stderr.WriteString(errResponse); err != nil {
			t.Fatalf("Failed writing stderr: %v", err)
		}
		if err := stderr.Flush(); err != nil {
			t.Fatalf("Failed flushing stderr: %v", err)
		}
		stdout := newWriter(conn, typeStdout, 1)
		if _, err := stdout.WriteString(response); err != nil {
			t.Fatalf("Failed writing response: %v", err)
		}
		if err := stdout.Close(); err != nil {
			t.Fatalf("Failed closing stdout: %v", err)
		}
		if err := stderr.Close(); err != nil {
			t.Fatalf("Failed closing stderr: %v", err)
		}
		if err := conn.writeEndRequest(1, 0, statusRequestComplete); err != nil {
			t.Fatalf("Failed ending request: %v", err)
		}
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err != nil {
		t.Fatalf("Failed to read stdin: %v", err)
	}
	if s, ok := equal(response, string(b.Bytes())); !ok {
		t.Fatalf("Wrong request content: %v", s)
	}
	if s, ok := equal(errResponse, string(errOut.Bytes())); !ok {
		t.Fatalf("Wrong error content: %v", s)
	}
	if err := h.wait(); err != nil {
		t.Fatalf("Failed waiting: %v", err)
	}
	wg.Wait()
}

func TestHostUnknownFrameType(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.writeRecord(42, 1, nil); err != nil {
			t.Fatalf("Failed writing record: %v", err)
		}
	}()

	if err := h.wait(); err == nil || !strings.Contains(err.Error(), "42") ||
		!strings.Contains(err.Error(), "unknown frame type") {
		t.Fatalf("Error did not contain 42 or unknown frame type: %v", err)
	}
	wg.Wait()
}

func TestHostWrongReqId(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		stdout := newWriter(conn, typeStdout, 271)
		if err := stdout.Close(); err != nil {
			t.Fatalf("Failed closing stdout: %v", err)
		}
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err == nil ||
		!strings.Contains(err.Error(), "requestId") {
		t.Fatalf("Error did not contain requestId: %v", err)
	}
	wg.Wait()
}

func TestHostUnexpectedManagementRecord(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		t.Fatalf("handle failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := conn.writeRecord(typeGetValuesResult, 0, nil); err != nil {
			t.Fatalf("Failed writing record: %v", err)
		}
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err == nil ||
		!strings.Contains(err.Error(), "10") ||
		!strings.Contains(err.Error(), "management record") {
		t.Fatalf("Error did not contain 10 or management record: %v", err)
	}
	wg.Wait()
}

func TestHostReadWriteError(t *testing.T) {
	reads, writes := countIos(t)
	for i := 0; i < reads; i++ {
		t.Run(fmt.Sprintf("read=%d", i), func(t *testing.T) {
			readWriteError(t, false, i)
		})
	}
	for i := 0; i < writes; i++ {
		t.Run(fmt.Sprintf("write=%d", i), func(t *testing.T) {
			readWriteError(t, true, i)
		})
	}
}

type ioCounter struct {
	io.ReadWriteCloser
	reads, writes int
}

func (cnt *ioCounter) Read(p []byte) (int, error) {
	cnt.reads++
	return cnt.ReadWriteCloser.Read(p)
}

func (cnt *ioCounter) Write(p []byte) (int, error) {
	cnt.writes++
	return cnt.ReadWriteCloser.Write(p)
}

func countIos(t *testing.T) (reads, writes int) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	counter := &ioCounter{ReadWriteCloser: bufWrite}
	if err := rweTrial(t, counter, bufRead); err != nil {
		t.Fatalf("Failed to count ios: %v", err)
	}
	return counter.reads, counter.writes
}

var flakyError error = errors.New("flaky error")

type flakyReadWriteCloser struct {
	io.ReadWriteCloser
	forWrite bool // whether ioCount is for reads or writes
	ioCount  int  // the io operation that should fail

	count     int
	triggered bool
}

func (f *flakyReadWriteCloser) Read(p []byte) (int, error) {
	if !f.forWrite {
		count := f.count
		f.count++
		if count == f.ioCount {
			f.triggered = true
			return 0, flakyError
		}
	}
	return f.ReadWriteCloser.Read(p)
}

func (f *flakyReadWriteCloser) Write(p []byte) (int, error) {
	if f.forWrite {
		count := f.count
		f.count++
		if count == f.ioCount {
			f.triggered = true
			return 0, flakyError
		}
	}
	return f.ReadWriteCloser.Write(p)
}

func readWriteError(t *testing.T, forWrite bool, ioCount int) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	frwc := &flakyReadWriteCloser{
		ReadWriteCloser: bufWrite,
		forWrite:        forWrite,
		ioCount:         ioCount,
	}
	if err := rweTrial(t, frwc, bufRead); !strings.Contains(err.Error(), flakyError.Error()) {
		t.Fatalf("expected flaky error, got: %v", err)
	}
	if !frwc.triggered {
		t.Fatalf("the flaky error was not triggered. Something is non-deterministic")
	}
}

func rweTrial(t *testing.T, bufWrite, bufRead io.ReadWriteCloser) (firstError error) {
	h := &host{
		conn: newConn(bufWrite),
		rec:  &record{},
	}
	conn := newConn(bufRead)
	var errorOnce sync.Once
	setError := func(err error) {
		errorOnce.Do(func() { firstError = err })
	}

	if _, _, err := handle(h, bufRead, nil, ""); err != nil {
		setError(err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := newWriter(conn, typeStdout, 1).Close(); err != nil {
			setError(err)
			return
		}
		if err := newWriter(conn, typeStderr, 1).Close(); err != nil {
			setError(err)
			return
		}
		if err := conn.writeEndRequest(1, 0, statusRequestComplete); err != nil {
			setError(err)
			return
		}
	}()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(h); err != nil {
		setError(err)
		return
	}
	if err := h.wait(); err != nil {
		setError(err)
		return
	}
	wg.Wait()
	return
}

func newPipeListener() *pipeListener {
	return &pipeListener{accept: make(chan net.Conn)}
}

type pipeListener struct {
	accept chan net.Conn
	closed bool
}

func (l *pipeListener) Accept() (net.Conn, error) {
	c, ok := <-l.accept
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *pipeListener) Close() error {
	close(l.accept)
	l.closed = true
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	panic("Unimplemented")
}

func (l *pipeListener) Dial(ctx context.Context) (net.Conn, error) {
	if l.closed {
		return nil, errors.New("listener closed")
	}
	clientConn, serverConn := net.Pipe()
	select {
	case l.accept <- serverConn:
		return clientConn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func BenchmarkGet(b *testing.B) {
	pl := newPipeListener()
	defer pl.Close()
	go fcgi.Serve(pl, nil)
	pd := newPoolingDialer(pl, 1)
	defer pd.Close()
	handler := &Handler{
		Dialer: pd,
		Root:   "/some",
	}
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	for i := 0; i < b.N; i++ {
		rw := &httptest.ResponseRecorder{}
		handler.ServeHTTP(rw, req)
	}
}

func BenchmarkPost(b *testing.B) {
	readBuffer := make([]byte, 32*1024)
	childHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := r.Body.Read(readBuffer); err != nil {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	pl := newPipeListener()
	defer pl.Close()
	go fcgi.Serve(pl, childHandler)
	pd := newPoolingDialer(pl, 1)
	defer pd.Close()
	handler := &Handler{
		Dialer: pd,
		Root:   "/some",
	}
	body := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		reqBody := bytes.NewBuffer(body)
		req := httptest.NewRequest(
			"POST", "http://example.com/some/path", reqBody)
		rw := &httptest.ResponseRecorder{}
		handler.ServeHTTP(rw, req)
	}
}

func BenchmarkConcurrentGet(b *testing.B) {
	concurrency := 5

	pl := newPipeListener()
	defer pl.Close()
	go fcgi.Serve(pl, nil)
	pd := newPoolingDialer(pl, concurrency)
	defer pd.Close()
	handler := &Handler{
		Dialer: pd,
		Root:   "/some",
	}
	workChan := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
			for range workChan {
				rw := &httptest.ResponseRecorder{}
				handler.ServeHTTP(rw, req)
			}
			wg.Done()
		}()
	}
	for i := 0; i < b.N; i++ {
		workChan <- struct{}{}
	}
	close(workChan)
	wg.Wait()
}

func newPoolingDialer(dialer Dialer, size int) *poolingDialer {
	return &poolingDialer{dialer, make(chan net.Conn, size)}
}

type poolingDialer struct {
	Dialer
	pool chan net.Conn
}

func (d *poolingDialer) Dial(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-d.pool:
		return conn, nil
	default:
		return d.Dialer.Dial(ctx)
	}
}

func (d *poolingDialer) put(conn net.Conn) error {
	select {
	case d.pool <- conn:
		return nil
	default:
		return conn.Close()
	}
}

func (d *poolingDialer) Close() error {
	close(d.pool)
	var err error
	for conn := range d.pool {
		if err2 := conn.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func equal(expected, actual interface{}) (msg string, ok bool) {
	if reflect.DeepEqual(expected, actual) {
		return "", true
	}
	msg = fmt.Sprintf("got: %v expected: %v", actual, expected)
	return msg, false
}

type nameValuePairs struct {
	m map[string]string
}

func (nvp *nameValuePairs) read(content []byte) error {
	nvp.m = make(map[string]string)
	for len(content) > 0 {
		nameLength, n := readSize(content)
		if n == 0 {
			return errors.New("Invalid name length")
		}
		content = content[n:]
		valueLength, n := readSize(content)
		if n == 0 {
			return errors.New("Invalid value length")
		}
		content = content[n:]
		if len(content) < int(nameLength)+int(valueLength) {
			return errors.New("Lengths exceed content")
		}
		name := readString(content, nameLength)
		content = content[nameLength:]
		value := readString(content, valueLength)
		content = content[valueLength:]
		nvp.m[name] = value
	}
	return nil
}
