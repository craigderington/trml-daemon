package exec

import (
	"bytes"
	"io"
	"time"
)

const (
	flushInterval = 50 * time.Millisecond
	flushSize     = 4 * 1024 // 4 KB
)

// ChunkWriter collects bytes and flushes them in chunks to a callback.
type ChunkWriter struct {
	buf      bytes.Buffer
	flushFn  func(chunk string)
	ticker   *time.Ticker
	done     chan struct{}
}

func NewChunkWriter(flushFn func(chunk string)) *ChunkWriter {
	cw := &ChunkWriter{
		flushFn: flushFn,
		ticker:  time.NewTicker(flushInterval),
		done:    make(chan struct{}),
	}
	go cw.timerLoop()
	return cw
}

func (cw *ChunkWriter) Write(p []byte) (int, error) {
	n, err := cw.buf.Write(p)
	if cw.buf.Len() >= flushSize {
		cw.flush()
	}
	return n, err
}

func (cw *ChunkWriter) timerLoop() {
	for {
		select {
		case <-cw.done:
			return
		case <-cw.ticker.C:
			cw.flush()
		}
	}
}

func (cw *ChunkWriter) flush() {
	if cw.buf.Len() == 0 {
		return
	}
	chunk := cw.buf.String()
	cw.buf.Reset()
	cw.flushFn(chunk)
}

// Close flushes remaining data and stops the timer.
func (cw *ChunkWriter) Close() error {
	cw.ticker.Stop()
	close(cw.done)
	cw.flush()
	return nil
}

// Ensure ChunkWriter implements io.WriteCloser.
var _ io.WriteCloser = (*ChunkWriter)(nil)
