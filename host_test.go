// Copyright 2017 Eric Anderson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fcgi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"sync"
	"testing"
)

func newTestListener() *testListener {
	return &testListener{accept: make(chan net.Conn)}
}

type testListener struct {
	accept chan net.Conn
	closed bool
}

func (l *testListener) Accept() (net.Conn, error) {
	c, ok := <-l.accept
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *testListener) Close() error {
	close(l.accept)
	l.closed = true
	return nil
}

func (l *testListener) Addr() net.Addr {
	panic("Unimplemented")
}

func (l *testListener) Dial(ctx context.Context) (net.Conn, error) {
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
	tl := newTestListener()
	defer tl.Close()
	go fcgi.Serve(tl, nil)
	pd := newPoolingDialer(tl, 1)
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

	tl := newTestListener()
	defer tl.Close()
	go fcgi.Serve(tl, childHandler)
	pd := newPoolingDialer(tl, 1)
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

	tl := newTestListener()
	defer tl.Close()
	go fcgi.Serve(tl, nil)
	pd := newPoolingDialer(tl, concurrency)
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
