package jsonclient

import (
	"math"
	"testing"
	"time"
)

const testLeeway = 10 * time.Microsecond

func fuzzyTimeEquals(a, b time.Time, leeway time.Duration) bool {
	diff := math.Abs(float64(a.Sub(b).Nanoseconds()))
	if diff < float64(leeway.Nanoseconds()) {
		return true
	}
	return false
}

func fuzzyDurationEquals(a, b time.Duration, leeway time.Duration) bool {
	diff := math.Abs(float64(a.Nanoseconds() - b.Nanoseconds()))
	if diff < float64(leeway.Nanoseconds()) {
		return true
	}
	return false
}

func TestBackoff(t *testing.T) {
	b := backoff{}

	// Test that the interval increases as expected
	for i := uint(0); i < maxMultiplier; i++ {
		n := time.Now()
		interval := b.set(nil)
		if interval != time.Second*(1<<i) {
			t.Fatalf("backoff.set() returned an unexpected duration. wanted: %s, got: %s", time.Second*(1<<i), interval)
		}
		expected := n.Add(interval)
		if !fuzzyTimeEquals(expected, b.notBefore, testLeeway) {
			t.Fatalf("backoff.notBefore is not expected time. wanted: %s (+/- 10µs), got: %s", expected, b.notBefore)
		}
		until := b.until()
		if !fuzzyTimeEquals(expected, until, maxJitter) {
			t.Fatalf("backoff.until() returned an unexpected time. wanted: %s (+ 0-250ms), got: %s", until, expected)
		}

		// reset notBefore
		b.notBefore = time.Time{}
	}

	// Test until returns the exact time without jitter if notBefore is in the past
	b.notBefore = time.Time{}
	nb := b.until()
	if !nb.Equal(time.Time{}) {
		t.Fatalf("backoff.until didn't return the exact backoff.notBefore when it was in the past: got: %s, wanted: %s", nb, b.until())
	}

	// Test that multiplier doesn't go above maxMultiplier
	b.multiplier = maxMultiplier
	b.notBefore = time.Time{}
	interval := b.set(nil)
	if b.multiplier > maxMultiplier {
		t.Fatalf("backoff.set() increased the multiplier more than maxMultiplier. got: %d, expected: %d", b.multiplier, maxMultiplier)
	}
	if interval > time.Second*(1<<maxMultiplier) {
		t.Fatalf("backoff.set() returned a interval larger than 128s. got: %s", interval)
	}

	// Test the override with smaller interval
	b.multiplier = 0
	b.notBefore = time.Now().Add(time.Hour)
	o := time.Second * 1800
	interval = b.set(&o)
	if !fuzzyDurationEquals(time.Hour, interval, testLeeway) {
		t.Fatalf("backoff.set() with override returned unexpected interval. got: %s, wanted: %s", interval, time.Hour)
	}

	// Test the override with larger interval
	b.multiplier = 0
	b.notBefore = time.Now().Add(time.Hour)
	o = time.Second * 7200
	interval = b.set(&o)
	if !fuzzyDurationEquals(2*time.Hour, interval, testLeeway) {
		t.Fatalf("backoff.set() with override returned unexpected interval. got: %s, wanted: %s", interval, 2*time.Hour)
	}

	// Test the override with current notBefore in the past
	b.multiplier = 0
	b.notBefore = time.Time{}
	o = time.Second * 7200
	interval = b.set(&o)
	if !fuzzyDurationEquals(2*time.Hour, interval, testLeeway) {
		t.Fatalf("backoff.set() with override returned unexpected interval. got: %s, wanted: %s", interval, 2*time.Hour)
	}

	// Test decreaseMultiplier properly decreases the multiplier
	b.multiplier = 1
	b.notBefore = time.Time{}
	b.decreaseMultiplier()
	if b.multiplier != 0 {
		t.Fatalf("backoff.decreaseMultiplier() returned unexpected multiplier. got: %d, wanted: %d", b.multiplier, 0)
	}

	// Test decreaseMultiplier doesn't reduce multiplier below 0
	b.decreaseMultiplier()
	if b.multiplier != 0 {
		t.Fatalf("backoff.decreaseMultiplier() returned unexpected multiplier. got: %d, wanted: %d", b.multiplier, 0)
	}
}
