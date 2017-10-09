package jsonclient

import (
	"math/rand"
	"sync"
	"time"
)

type backoff struct {
	mu         sync.RWMutex
	multiplier uint
	notBefore  time.Time
}

const (
	// maximum backoff is 2^(maxMultiplier-1) = 128 seconds
	maxMultiplier = 8
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
		if b.multiplier < maxMultiplier {
			b.multiplier++
		}
		wait = time.Second * time.Duration(1<<(b.multiplier-1))
	}
	b.notBefore = time.Now().Add(wait)
	return wait
}

func (b *backoff) decreaseMultiplier() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.multiplier > 0 {
		b.multiplier--
	}
}

func (b *backoff) until() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.notBefore.Before(time.Now()) {
		return b.notBefore
	}
	return b.notBefore.Add(time.Millisecond * time.Duration(rand.Intn(int(maxJitter.Seconds()*1000))))
}
