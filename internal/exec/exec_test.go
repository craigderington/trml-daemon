package exec_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/exec"
	"github.com/craigderington/trml-daemon/internal/protocol"
)

// ── ChunkWriter ───────────────────────────────────────────────────────────────

func TestChunkWriter_FlushOnSize(t *testing.T) {
	var mu sync.Mutex
	var chunks []string

	cw := exec.NewChunkWriter(func(chunk string) {
		mu.Lock()
		chunks = append(chunks, chunk)
		mu.Unlock()
	})

	// Write exactly 4KB + 1 byte — should flush immediately
	data := make([]byte, 4*1024+1)
	for i := range data {
		data[i] = 'x'
	}
	cw.Write(data)

	mu.Lock()
	flushed := len(chunks) > 0
	mu.Unlock()

	if !flushed {
		t.Error("expected flush when 4KB threshold crossed")
	}
	cw.Close()
}

func TestChunkWriter_FlushOnTimer(t *testing.T) {
	var mu sync.Mutex
	var chunks []string

	cw := exec.NewChunkWriter(func(chunk string) {
		mu.Lock()
		chunks = append(chunks, chunk)
		mu.Unlock()
	})
	defer cw.Close()

	// Write small data — should not flush immediately
	cw.Write([]byte("small"))

	mu.Lock()
	immediateFlushed := len(chunks) > 0
	mu.Unlock()

	if immediateFlushed {
		// OK — may have flushed already depending on timing
		return
	}

	// Wait for timer (50ms interval + buffer)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	timerFlushed := len(chunks) > 0
	mu.Unlock()

	if !timerFlushed {
		t.Error("expected timer flush within 200ms")
	}
}

func TestChunkWriter_CloseFlushesRemaining(t *testing.T) {
	var mu sync.Mutex
	var chunks []string

	cw := exec.NewChunkWriter(func(chunk string) {
		mu.Lock()
		chunks = append(chunks, chunk)
		mu.Unlock()
	})

	cw.Write([]byte("leftover"))
	cw.Close() // must flush synchronously

	mu.Lock()
	total := strings.Join(chunks, "")
	mu.Unlock()

	if total != "leftover" {
		t.Errorf("expected 'leftover', got %q (chunks: %v)", total, chunks)
	}
}

func TestChunkWriter_EmptyFlushIsNoop(t *testing.T) {
	called := false
	cw := exec.NewChunkWriter(func(chunk string) { called = true })
	cw.Close() // flush called with no data → should not invoke callback

	if called {
		t.Error("flush callback should not be called on empty buffer")
	}
}

// ── Runner ────────────────────────────────────────────────────────────────────

func TestRunner_Execute_Success(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var mu sync.Mutex
	var payloads []protocol.OutputPayload

	r.Execute(context.Background(), "dev1", "cmd1", "echo hello", func(p protocol.OutputPayload) {
		mu.Lock()
		payloads = append(payloads, p)
		mu.Unlock()
	})

	mu.Lock()
	defer mu.Unlock()

	if len(payloads) == 0 {
		t.Fatal("expected at least one payload")
	}

	last := payloads[len(payloads)-1]
	if !last.Done {
		t.Error("last payload should have Done=true")
	}
	if last.ExitCode == nil || *last.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %v", last.ExitCode)
	}

	combined := ""
	for _, p := range payloads {
		combined += p.Chunk
	}
	if !strings.Contains(combined, "hello") {
		t.Errorf("expected 'hello' in output, got: %q", combined)
	}
}

func TestRunner_Execute_NonZeroExitCode(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var last protocol.OutputPayload
	r.Execute(context.Background(), "dev1", "cmd2", "exit 42", func(p protocol.OutputPayload) {
		if p.Done {
			last = p
		}
	})

	if last.ExitCode == nil || *last.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %v", last.ExitCode)
	}
}

func TestRunner_Execute_StderrCaptured(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var chunks []string
	r.Execute(context.Background(), "dev1", "cmd3", "echo err >&2", func(p protocol.OutputPayload) {
		if p.Chunk != "" {
			chunks = append(chunks, p.Chunk)
		}
	})

	combined := strings.Join(chunks, "")
	if !strings.Contains(combined, "err") {
		t.Errorf("expected stderr in output, got: %q", combined)
	}
}

func TestRunner_Execute_MultilineOutput(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var chunks []string
	var mu sync.Mutex

	r.Execute(context.Background(), "dev1", "cmd4", "printf 'line1\nline2\nline3\n'", func(p protocol.OutputPayload) {
		if p.Chunk != "" {
			mu.Lock()
			chunks = append(chunks, p.Chunk)
			mu.Unlock()
		}
	})

	combined := strings.Join(chunks, "")
	for _, want := range []string{"line1", "line2", "line3"} {
		if !strings.Contains(combined, want) {
			t.Errorf("missing %q in output: %q", want, combined)
		}
	}
}

func TestRunner_Execute_DonePayloadHasCorrectID(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var doneID string
	r.Execute(context.Background(), "dev1", "unique-cmd-id", "true", func(p protocol.OutputPayload) {
		if p.Done {
			doneID = p.ID
		}
	})

	if doneID != "unique-cmd-id" {
		t.Errorf("expected done ID 'unique-cmd-id', got %q", doneID)
	}
}

func TestRunner_Execute_Cancelled(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{}, 1)
	doneCh := make(chan protocol.OutputPayload, 1)

	go func() {
		r.Execute(ctx, "dev1", "long-cmd", "echo start && sleep 10", func(p protocol.OutputPayload) {
			if strings.Contains(p.Chunk, "start") {
				select {
				case started <- struct{}{}:
				default:
				}
			}
			if p.Done {
				doneCh <- p
			}
		})
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("command did not start in time")
	}

	cancel()

	select {
	case last := <-doneCh:
		if last.ExitCode == nil || *last.ExitCode == 0 {
			t.Errorf("expected non-zero exit code after cancel, got %v", last.ExitCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for done payload after cancel")
	}
}

func TestRunner_Cancel_InFlight(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	started := make(chan struct{})
	done := make(chan struct{})
	var exitCode int

	go func() {
		r.Execute(context.Background(), "dev1", "cancel-me", "echo started && sleep 10", func(p protocol.OutputPayload) {
			if strings.Contains(p.Chunk, "started") {
				close(started)
			}
			if p.Done && p.ExitCode != nil {
				exitCode = *p.ExitCode
				close(done)
			}
		})
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("command did not start")
	}

	r.Cancel("cancel-me")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("command did not complete after cancel")
	}

	if exitCode == 0 {
		t.Error("expected non-zero exit code after cancel")
	}
}

func TestRunner_Cancel_NotFound(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())
	// Should not panic
	r.Cancel("nonexistent-id")
}

func TestRunner_Execute_StructuredOutput_Df(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var last protocol.OutputPayload
	r.Execute(context.Background(), "dev1", "df-cmd", "df -h", func(p protocol.OutputPayload) {
		if p.Done {
			last = p
		}
	})

	if last.ExitCode == nil || *last.ExitCode != 0 {
		t.Skip("df -h failed — skipping structured output check")
	}
	if last.Structured == nil {
		t.Error("expected structured output for 'df -h'")
	}
}

func TestRunner_Execute_NoStructuredOutput_UnknownCmd(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var last protocol.OutputPayload
	r.Execute(context.Background(), "dev1", "uname-cmd", "uname -a", func(p protocol.OutputPayload) {
		if p.Done {
			last = p
		}
	})

	if last.Structured != nil {
		t.Error("unexpected structured output for 'uname -a'")
	}
}

func TestRunner_Execute_ConcurrentCommands(t *testing.T) {
	r := exec.NewRunner(zap.NewNop())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var got string
			r.Execute(context.Background(), "dev1", "concurrent-cmd", "echo concurrent", func(p protocol.OutputPayload) {
				got += p.Chunk
			})
			if !strings.Contains(got, "concurrent") {
				t.Errorf("goroutine %d: unexpected output: %q", n, got)
			}
		}(i)
	}
	wg.Wait()
}
