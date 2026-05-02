package relay

import (
	"context"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

const (
	reconnectMin    = 1 * time.Second
	reconnectMax    = 60 * time.Second
	reconnectJitter = 0.1
)

// RunWithReconnect calls connect in a loop, backing off exponentially on failure.
// connect should block until the connection closes.
func RunWithReconnect(ctx context.Context, log *zap.Logger, connect func(context.Context) error) {
	delay := reconnectMin
	for {
		if ctx.Err() != nil {
			return
		}

		err := connect(ctx)

		if ctx.Err() != nil {
			return
		}

		if err != nil {
			log.Warn("relay connection failed", zap.Error(err), zap.Duration("retry_in", delay))
		} else {
			log.Info("relay disconnected, reconnecting", zap.Duration("retry_in", delay))
		}

		// Wait with jitter
		jitter := time.Duration(float64(delay) * reconnectJitter * (rand.Float64()*2 - 1))
		wait := delay + jitter
		if wait < 0 {
			wait = reconnectMin
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		// Double delay, cap at max
		delay *= 2
		if delay > reconnectMax {
			delay = reconnectMax
		}
	}
}
