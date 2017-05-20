package fcgi

import (
	"errors"
	"fmt"
	"io"
)

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
