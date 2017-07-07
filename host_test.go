package fcgi

import (
	"bytes"
	"io"
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
