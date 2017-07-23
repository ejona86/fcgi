package fcgi

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http/fcgi"
	"net/http/httptest"
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

func TestHandshake(t *testing.T) {
	bufWrite, bufRead := testPipe()
	defer bufRead.Close()
	conn := newConn(bufRead)

	var rec record
	var c *Client
	var err error
	if c, err = NewClient(bufWrite); err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}
	if err := rec.read(bufRead); err != nil {
		t.Fatalf("couldn't get initial record: %v", err)
	}
	if rec.h.Type != typeGetValues || rec.h.Id != 0 {
		t.Fatalf("got %v instead of GetValues", rec.h)
	}
	getValuesResult := map[string]string{
		"FCGI_MAX_REQS":   "2",
		"FCGI_MPXS_CONNS": "1",
	}
	if err := conn.writeDiscretePairs(typeGetValuesResult, 0, getValuesResult); err != nil {
		t.Fatalf("failed writing GetValuesResult: %v", err)
	}
	c.host.mutex.Lock()
	maxReqs := c.host.maxReqs
	c.host.mutex.Unlock()
	if maxReqs != 2 {
		t.Fatalf("maxReqs: got %d expected %d", maxReqs, 2)
	}
}

func BenchmarkGet(b *testing.B) {
	hostConn, childConn := net.Pipe()
	l := singleConnectionListener{childConn}
	fcgi.Serve(&l, nil)
	client, err := NewClient(hostConn)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	handler := &Handler{
		Dialer: fixedDialer{client},
		Root:   "/some",
	}
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	for i := 0; i < b.N; i++ {
		rw := &httptest.ResponseRecorder{}
		handler.ServeHTTP(rw, req)
	}
}

func BenchmarkConcurrentGet(b *testing.B) {
	hostConn, childConn := net.Pipe()
	l := singleConnectionListener{childConn}
	fcgi.Serve(&l, nil)
	client, err := NewClient(hostConn)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	handler := &Handler{
		Dialer: fixedDialer{client},
		Root:   "/some",
	}
	workChan := make(chan struct{})
	concurrency := 5
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

type fixedDialer struct {
	c *Client
}

func (d fixedDialer) Dial(ctx context.Context) (*Client, error) {
	return d.c, nil
}

func (d fixedDialer) Close(client *Client) {}

type singleConnectionListener struct {
	conn net.Conn
}

func (l *singleConnectionListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *singleConnectionListener) Close() error {
	return nil
}

func (l *singleConnectionListener) Addr() net.Addr {
	return nil
}
