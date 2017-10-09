package jsonclient

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"
)

type backoff struct {
	mu         sync.RWMutex
	multiplier int64
	notBefore  time.Time
}

const (
	// maximum backoff is 2^(maxMultiplier-1) = 128 seconds
	maxMultiplier = 8
	maxJitter     = 250 * time.Millisecond
)

func (b *backoff) set(override *time.Duration) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.notBefore.After(time.Now()) {
		if override != nil {
			// If existing backoff is set but override would be longer than
			// it then set it to that.
			notBefore := time.Now().Add(*override)
			if notBefore.After(b.notBefore) {
				b.notBefore = notBefore
			}
		}
		return time.Until(b.notBefore)
	}
	var wait time.Duration
	if override != nil {
		wait = *override
	} else {
		if b.multiplier <= maxMultiplier {
			b.multiplier++
		}
		wait = time.Second * time.Duration(math.Pow(2, float64(b.multiplier-1)))
	}
	notBefore := time.Now().Add(wait)
	b.notBefore = notBefore
	return wait
}

func (b *backoff) decreaseMultiplier() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.multiplier > 0 {
		b.multiplier--
	}
}

func (b *backoff) backoff(ctx context.Context) error {
	b.mu.RLock()
	if b.notBefore.Before(time.Now()) {
		b.mu.RUnlock()
		return nil
	}
	// add jitter so everything that is waiting doesn't fire all at the same time
	sleepDur := time.Until(b.notBefore)
	b.mu.RUnlock()
	sleepDur += time.Millisecond * time.Duration(rand.Intn(int(maxJitter.Seconds()*1000)))
	backoffTimer := time.NewTimer(sleepDur)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-backoffTimer.C:
	}
	return nil
}
