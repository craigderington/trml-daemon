package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/parser"
	"github.com/craigderington/trml-daemon/internal/protocol"
)

// DefaultCommandTimeout is the default command execution timeout (5 minutes).
const DefaultCommandTimeout = 5 * time.Minute

// OutputCallback is called with each output chunk and the final done message.
type OutputCallback func(payload protocol.OutputPayload)

// Runner executes shell commands and streams output.
type Runner struct {
	mu          sync.Mutex
	cancels     map[string]context.CancelFunc
	log         *zap.Logger
	rawShellMode bool // when true, skip validation but log warnings
	timeout      time.Duration
}

func NewRunner(log *zap.Logger, rawShellMode ...bool) *Runner {
	return NewRunnerWithTimeout(log, DefaultCommandTimeout, rawShellMode...)
}

// NewRunnerWithTimeout creates a Runner with an explicit command timeout.
// Pass 0 to disable the timeout (commands run indefinitely).
func NewRunnerWithTimeout(log *zap.Logger, timeout time.Duration, rawShellMode ...bool) *Runner {
	enableRaw := len(rawShellMode) > 0 && rawShellMode[0]
	return &Runner{
		cancels:      make(map[string]context.CancelFunc),
		log:          log,
		rawShellMode: enableRaw,
		timeout:      timeout,
	}
}

// Execute runs a shell command and streams output via callback.
func (r *Runner) Execute(parentCtx context.Context, deviceID, cmdID, command string, cb OutputCallback) {
	ctx, cancel := context.WithCancel(parentCtx)

	// Apply configurable timeout on top of the parent context.
	if r.timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, r.timeout)
		defer func() {
			// Cancel both: explicit cancel (from r.Cancel or done) and timeout cancel.
			cancel()
			timeoutCancel()
		}()
	} else {
		defer cancel()
	}

	r.mu.Lock()
	r.cancels[cmdID] = cancel
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.cancels, cmdID)
		r.mu.Unlock()
		cancel()
	}()

	r.log.Info("executing command",
		zap.String("id", cmdID),
		zap.String("device", deviceID),
		zap.String("command", command),
		zap.Duration("timeout", r.timeout),
	)

	// ── Command validation / sandboxing ───────────────────────────────────────
	if !r.rawShellMode {
		sanitized, err := SanitizeCommand(command)
		if err != nil {
			r.log.Warn("command blocked by sanitizer",
				zap.String("id", cmdID),
				zap.String("device", deviceID),
				zap.String("original", command),
				zap.Error(err),
			)
			exitCode := 1
			cb(protocol.OutputPayload{
				Type:     protocol.TypeOutput,
				ID:       cmdID,
				Done:     true,
				ExitCode: &exitCode,
				Chunk:    fmt.Sprintf("Command blocked: %s", err.Error()),
			})
			return
		}

		if sanitized != command {
			r.log.Info("command sanitized",
				zap.String("id", cmdID),
				zap.String("original", command),
				zap.String("sanitized", sanitized),
			)
			command = sanitized
		}
	} else {
		r.log.Warn("raw shell mode enabled — skipping command validation",
			zap.String("id", cmdID),
			zap.String("device", deviceID),
		)
	}

	var fullOutput bytes.Buffer
	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	// Put the process in its own process group so cancellation kills all
	// child processes (e.g. sleep spawned by sh), not just the direct child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Override the default kill to kill the entire process group.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			syscall.Kill(-pgid, syscall.SIGKILL)
		}
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 3 * time.Second

	chunkWriter := NewChunkWriter(func(chunk string) {
		cb(protocol.OutputPayload{
			Type:  protocol.TypeOutput,
			ID:    cmdID,
			Chunk: chunk,
			Done:  false,
		})
	})

	multiWriter := &multiWriteCloser{writers: []interface{}{chunkWriter, &fullOutput}}
	cmd.Stdout = multiWriter
	cmd.Stderr = multiWriter

	runErr := cmd.Run()
	chunkWriter.Close()

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() != nil {
			exitCode = -1
		} else {
			exitCode = 1
		}
	}

	// Build done payload, optionally with structured data
	done := protocol.OutputPayload{
		Type:     protocol.TypeOutput,
		ID:       cmdID,
		Done:     true,
		ExitCode: &exitCode,
	}

	if p := parser.FindParser(command); p != nil {
		if structured, err := p.Parse(fullOutput.String()); err == nil {
			if data, err := json.Marshal(structured); err == nil {
				done.Structured = data
			}
		}
	}

	cb(done)
}

// Cancel cancels an in-flight command by ID.
func (r *Runner) Cancel(cmdID string) {
	r.mu.Lock()
	cancel, ok := r.cancels[cmdID]
	r.mu.Unlock()
	if ok {
		cancel()
	}
}

// multiWriteCloser writes to multiple destinations.
type multiWriteCloser struct {
	writers []interface{}
}

func (m *multiWriteCloser) Write(p []byte) (int, error) {
	for _, w := range m.writers {
		switch ww := w.(type) {
		case *ChunkWriter:
			ww.Write(p)
		case *bytes.Buffer:
			ww.Write(p)
		}
	}
	return len(p), nil
}
