package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/apns"
	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/exec"
	"github.com/craigderington/trml-daemon/internal/pairing"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"github.com/craigderington/trml-daemon/internal/relay"
)

// openPIDFile opens the PID file with exclusive flock to prevent duplicate daemon instances.
// Returns the opened *os.File; caller must close it (or lock is released on process exit).
func openPIDFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open PID file: %w", err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, fmt.Errorf("truncate PID file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("PID file already locked by another instance (flock): %w", err)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync PID file: %w", err)
	}
	return f, nil
}

// closePIDFile releases the flock and removes the PID file.
func closePIDFile(f *os.File) {
	if f == nil {
		return
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
	os.Remove(config.PIDPath())
}

// StatusJSON is written periodically to status.json.
type StatusJSON struct {
	Connected    bool      `json:"connected"`
	Uptime       string    `json:"uptime"`
	PairedCount  int       `json:"paired_count"`
	StartedAt    time.Time `json:"started_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}


// machineInfo returns OS name, default shell, and hostname for the hello message.
func machineInfo() (osName, shell, hostname string) {
	switch runtime.GOOS {
	case "darwin":
		osName = "macOS"
	case "linux":
		osName = "Linux"
	default:
		osName = runtime.GOOS
	}
	shell = os.Getenv("SHELL")
	if shell == "" {
		shell = "sh"
	} else {
		// keep only the basename, e.g. "/bin/zsh" → "zsh"
		parts := strings.Split(shell, "/")
		shell = parts[len(parts)-1]
	}
	hostname, _ = os.Hostname()
	return
}

// Run wires all components and blocks until context is cancelled.
func Run(cfg *config.Config, log *zap.Logger) error {
	startedAt := time.Now()

	// Write PID file with exclusive flock (prevents duplicate instances)
	pidFile, err := openPIDFile(config.PIDPath())
	if err != nil {
		return fmt.Errorf("acquire PID lock: %w", err)
	}
	defer closePIDFile(pidFile)

	// Context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Resolve public key
	pubKeyB64, err := crypto.PublicKeyFromPrivateB64(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	// Build relay client
	relayClient := relay.NewClient(cfg.RelayURL, cfg.DeviceID, pubKeyB64, log)

	// Declare encryptSend and pairMgr as vars so OnConnect can close over them
	// before they are assigned below (closures capture by reference in Go).
	var encryptSend func(deviceID string, key []byte, payload []byte) error
	var pairMgr *pairing.Manager

	connected := false
	relayClient.OnConnect(func() {
		connected = true
		// Send hello to every paired device so iOS NL mode has real machine context.
		osName, shell, hostname := machineInfo()
		for _, dev := range cfg.PairedDevices {
			key, err := pairMgr.GetSessionKey(dev.DeviceID)
			if err != nil {
				continue // device not yet fully paired
			}
			hello, _ := protocol.MarshalInner(protocol.HelloPayload{
				Type:     protocol.TypeHello,
				OSName:   osName,
				Shell:    shell,
				Hostname: hostname,
			})
			_ = encryptSend(dev.DeviceID, key, hello)
		}
	})
	relayClient.OnDisconnect(func() { connected = false })

	// EncryptSend sends an encrypted payload to a device via the relay.
	encryptSend = func(deviceID string, key []byte, payload []byte) error {
		data, err := relay.BuildEncryptedEnvelope(cfg.DeviceID, key, payload, func(k, p []byte) ([]byte, []byte, error) {
			return crypto.Seal(k, p)
		})
		if err != nil {
			return err
		}
		if !relayClient.Send(data) {
			return fmt.Errorf("send buffer full")
		}
		return nil
	}

	// Build pairing manager
	pairMgr = pairing.NewManager(cfg, log, encryptSend)

	// After a new pairing send a hello immediately (before the next reconnect).
	pairMgr.SetOnPaired(func(deviceID string, key []byte) {
		osName, shell, hostname := machineInfo()
		hello, _ := protocol.MarshalInner(protocol.HelloPayload{
			Type:     protocol.TypeHello,
			OSName:   osName,
			Shell:    shell,
			Hostname: hostname,
		})
		_ = encryptSend(deviceID, key, hello)
	})

	// APNs client — only created when credentials are fully configured.
	var apnsClient *apns.Client
	if cfg.APNs.IsConfigured() {
		apnsClient, err = apns.NewClient(apns.Config{
			KeyPath:  cfg.APNs.KeyPath,
			KeyID:    cfg.APNs.KeyID,
			TeamID:   cfg.APNs.TeamID,
			BundleID: "app.trml",
			Sandbox:  cfg.APNs.Sandbox,
		})
		if err != nil {
			log.Warn("APNs client init failed — push notifications disabled", zap.Error(err))
			apnsClient = nil
		} else {
			log.Info("APNs push notifications enabled")
		}
	}

	// apnsTokens stores the latest APNs device token per paired iOS device.
	var apnsTokensMu sync.RWMutex
	apnsTokens := make(map[string]string) // deviceID → hex token

	// Pre-populate from persisted config so push works after a daemon restart.
	for _, dev := range cfg.PairedDevices {
		if dev.APNsToken != "" {
			apnsTokens[dev.DeviceID] = dev.APNsToken
		}
	}

	// Build command runner (pass raw shell mode and configured timeout)
	timeout := time.Duration(cfg.CommandTimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = exec.DefaultCommandTimeout // fallback default
	}
	// Merge any user-supplied extra commands before creating the runner.
	if len(cfg.AllowedCommands) > 0 {
		exec.AddExtraAllowedCommands(cfg.AllowedCommands)
		log.Info("extra allowed commands loaded from config", zap.Strings("commands", cfg.AllowedCommands))
	}
	r := exec.NewRunnerWithTimeout(log, timeout, cfg.RawShellMode)

	// onExec handles incoming exec requests
	onExec := func(deviceID string, p protocol.ExecPayload) {
		go r.Execute(ctx, deviceID, p.ID, p.Command, func(out protocol.OutputPayload) {
			key, err := pairMgr.GetSessionKey(deviceID)
			if err != nil {
				log.Error("no session key for output", zap.Error(err))
				return
			}
			outPayload, err := protocol.MarshalInner(out)
			if err != nil {
				log.Error("marshal output", zap.Error(err))
				return
			}
			if err := encryptSend(deviceID, key, outPayload); err != nil {
				log.Error("send output", zap.Error(err))
			}
			// Send APNs push when the command finishes, if we have the token.
			if out.Done && apnsClient != nil {
				apnsTokensMu.RLock()
				tok := apnsTokens[deviceID]
				apnsTokensMu.RUnlock()
				if tok != "" {
					exitCode := 0
					if out.ExitCode != nil {
						exitCode = *out.ExitCode
					}
					title := "Command finished"
					if exitCode != 0 {
						title = fmt.Sprintf("Command failed (exit %d)", exitCode)
					}
					body := p.Command
					if len(body) > 80 {
						body = body[:77] + "..."
					}
					go func() {
						if err := apnsClient.Notify(tok, title, body, cfg.DeviceID); err != nil {
							log.Warn("APNs push failed", zap.Error(err),
								zap.String("device_id", deviceID))
						}
					}()
				}
			}
		})
	}

	// onCancel handles cancel requests
	onCancel := func(deviceID string, p protocol.CancelPayload) {
		r.Cancel(p.ID)
	}

	// onComplete handles tab-completion requests — run compgen and reply.
	onComplete := func(deviceID string, p protocol.CompletePayload) {
		candidates := exec.Complete(p.Line, p.Prefix)
		ack, err := protocol.MarshalInner(protocol.CompleteAckPayload{
			Type:        protocol.TypeCompleteAck,
			ID:          p.ID,
			Completions: candidates,
			Prefix:      p.Prefix,
		})
		if err != nil {
			log.Error("marshal complete_ack", zap.Error(err))
			return
		}
		key, err := pairMgr.GetSessionKey(deviceID)
		if err != nil {
			log.Warn("no session key for complete_ack", zap.String("device_id", deviceID), zap.Error(err))
			return
		}
		if err := encryptSend(deviceID, key, ack); err != nil {
			log.Error("send complete_ack", zap.Error(err))
		}
	}

	// Build message handler
	msgHandler := relay.NewMessageHandler(
		pairMgr.GetSessionKey,
		crypto.Open,
		pairMgr.HandlePairRequest,
		onExec,
		onCancel,
		log,
	)

	msgHandler.SetCompleteHandler(onComplete)

	// onPushRegister stores the APNs token and persists it to config.
	msgHandler.SetPushRegHandler(func(deviceID string, pr protocol.PushRegisterPayload) {
		if pr.APNsToken == "" {
			return
		}
		apnsTokensMu.Lock()
		apnsTokens[deviceID] = pr.APNsToken
		apnsTokensMu.Unlock()

		// Persist token so it survives daemon restarts.
		for i := range cfg.PairedDevices {
			if cfg.PairedDevices[i].DeviceID == deviceID {
				cfg.PairedDevices[i].APNsToken = pr.APNsToken
				if err := config.Save(cfg); err != nil {
					log.Warn("failed to persist APNs token", zap.Error(err))
				}
				break
			}
		}
		log.Info("APNs token registered", zap.String("device_id", deviceID))
	})

	relayClient.OnMessage(msgHandler.Handle)

	// Status writer goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				writeStatus(cfg, connected, startedAt, pairMgr.PairedCount())
			}
		}
	}()
	// Write initial status
	writeStatus(cfg, false, startedAt, pairMgr.PairedCount())

	log.Info("trml daemon starting",
		zap.String("device_id", cfg.DeviceID),
		zap.String("relay", cfg.RelayURL),
	)

	// Show QR if no paired devices
	if !pairMgr.IsPaired() {
		pubB64, deviceID, relayHost, err := pairMgr.QRInfo()
		if err == nil {
			pairing.PrintQR(pubB64, deviceID, relayHost)
		}
	}

	// Reconnect loop (blocks until ctx cancelled)
	relay.RunWithReconnect(ctx, log, relayClient.Connect)

	log.Info("trml daemon stopped")
	writeStatus(cfg, false, startedAt, pairMgr.PairedCount())
	return nil
}

func writeStatus(cfg *config.Config, connected bool, startedAt time.Time, pairedCount int) {
	s := StatusJSON{
		Connected:   connected,
		Uptime:      time.Since(startedAt).Round(time.Second).String(),
		PairedCount: pairedCount,
		StartedAt:   startedAt,
		UpdatedAt:   time.Now(),
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(config.StatusPath(), data, 0644)
}
