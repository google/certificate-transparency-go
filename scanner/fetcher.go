// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/trillian/client/backoff"
)

// FetcherOptions holds configuration options for the Fetcher.
type FetcherOptions struct {
	// Number of entries to request in one batch from the Log.
	BatchSize int

	// Number of concurrent fetcher workers to run.
	ParallelFetch int

	// [StartIndex, EndIndex) is a log entry range to fetch. If EndIndex == 0,
	// then it gets reassigned to sth.TreeSize.
	StartIndex int64
	EndIndex   int64

	// Continuous determines whether Fetcher should run indefinitely after
	// reaching EndIndex.
	Continuous bool

	// Don't print any status messages to default logger.
	Quiet bool
}

// DefaultFetcherOptions returns new FetcherOptions with sensible defaults.
func DefaultFetcherOptions() *FetcherOptions {
	return &FetcherOptions{
		BatchSize:     1000,
		ParallelFetch: 1,
		StartIndex:    0,
		EndIndex:      0,
		Continuous:    false,
		Quiet:         false,
	}
}

// Fetcher is a tool that fetches entries from a CT Log.
type Fetcher struct {
	// Client used to talk to the CT log instance.
	client *client.LogClient
	// Configuration options for this Fetcher instance.
	opts *FetcherOptions

	// Current STH of the Log this Fetcher sends queries to.
	sth *ct.SignedTreeHead
	// The STH retrieval backoff state. Used only in Continuous fetch mode.
	sthBackoff *backoff.Backoff

	// TODO(pavelkalinnikov): Consider log.Logger instead.
	Log func(msg string)
}

// EntryBatch represents a contiguous range of entries of the Log.
type EntryBatch struct {
	Start   int64          // LeafIndex of the first entry in the range.
	Entries []ct.LeafEntry // Entries of the range.
}

// fetchRange represents a range of certs to fetch from a CT log.
type fetchRange struct {
	start int64 // inclusive
	end   int64 // inclusive
}

// NewFetcher creates a Fetcher instance using client to talk to the log,
// taking configuration options from opts.
func NewFetcher(client *client.LogClient, opts *FetcherOptions) *Fetcher {
	fetcher := &Fetcher{client: client, opts: opts}
	if opts.Quiet {
		fetcher.Log = func(msg string) {}
	} else {
		fetcher.Log = func(msg string) { log.Print(msg) }
	}
	return fetcher
}

// Prepare caches the latest Log's STH if not present and returns it. It also
// adjusts the entry range to fit the size of the tree.
func (f *Fetcher) Prepare(ctx context.Context) (*ct.SignedTreeHead, error) {
	if f.sth != nil {
		return f.sth, nil
	}

	sth, err := f.client.GetSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetSTH() failed: %v", err)
	}
	f.Log(fmt.Sprintf("Got STH with %d certs", sth.TreeSize))
	if f.opts.EndIndex == 0 || f.opts.EndIndex > int64(sth.TreeSize) {
		f.opts.EndIndex = int64(sth.TreeSize)
	}
	f.sth = sth
	return sth, nil
}

// Run performs fetching of the Log. Blocks until scanning is complete or
// context is cancelled. For each successfully fetched batch, runs the fn
// callback.
func (f *Fetcher) Run(ctx context.Context, fn func(EntryBatch)) error {
	f.Log("Starting up Fetcher...\n")
	if _, err := f.Prepare(ctx); err != nil {
		return err
	}

	ranges := f.genRanges(ctx)

	// Run fetcher workers.
	var wg sync.WaitGroup
	for w, cnt := 0, f.opts.ParallelFetch; w < cnt; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f.runWorker(ctx, ranges, fn)
			f.Log(fmt.Sprintf("Fetcher worker %d finished", idx))
		}(w)
	}
	wg.Wait()

	return nil
}

// genRanges returns a channel of ranges to fetch, and starts a goroutine that
// sends things down this channel. The goroutine terminates when all ranges
// have been generated, or if context is cancelled.
func (f *Fetcher) genRanges(ctx context.Context) <-chan fetchRange {
	batch := int64(f.opts.BatchSize)
	ranges := make(chan fetchRange)

	go func() {
		defer close(ranges)
		start, end := f.opts.StartIndex, f.opts.EndIndex

		for start < end {
			batchEnd := start + min(end-start, batch)
			next := fetchRange{start, batchEnd - 1}
			select {
			case <-ctx.Done():
				f.Log(fmt.Sprintf("genRanges cancelled: %v", ctx.Err()))
				return
			case ranges <- next:
			}
			start = batchEnd

			if start == end && f.opts.Continuous {
				if err := f.updateSTH(ctx); err != nil {
					f.Log(fmt.Sprintf("STH update cancelled: %v", err))
					return
				}
				end = f.opts.EndIndex
			}
		}
	}()

	return ranges
}

// updateSTH waits until a bigger STH is discovered, and updates the Fetcher
// accordingly. It is optimized for both bulk-load (new STH is way bigger then
// the last one) and keep-up (STH grows slowly) modes of operation. Waits for
// some time until the STH grows enough to request a full batch, but falls back
// to *any* STH bigger than the old one if it takes too long.
// Returns error only if the context is cancelled.
func (f *Fetcher) updateSTH(ctx context.Context) error {
	const quickDur = 30 * time.Second
	if f.sthBackoff == nil {
		f.sthBackoff = &backoff.Backoff{
			Min:    500 * time.Millisecond,
			Max:    20 * time.Second,
			Factor: 2,
			Jitter: true,
		}
	}

	lastSize := uint64(f.opts.EndIndex)
	targetSize := lastSize + uint64(f.opts.BatchSize)
	start := time.Now()

	return f.sthBackoff.Retry(ctx, func() error {
		sth, err := f.client.GetSTH(ctx)
		if err != nil {
			return err
		}
		f.Log(fmt.Sprintf("Got STH with %d certs", sth.TreeSize))

		quick := (time.Now().Sub(start) < quickDur)
		if sth.TreeSize <= lastSize || quick && sth.TreeSize < targetSize {
			return errors.New("waiting for bigger STH")
		}

		if quick {
			f.sthBackoff.Reset() // Growth is presumably fast, set next pause to Min.
		}
		f.sth = sth
		f.opts.EndIndex = int64(sth.TreeSize)
		return nil
	})
}

// runWorker is a worker function for handling fetcher ranges.
// Accepts cert ranges to fetch over the ranges channel, and if the fetch is
// successful sends the corresponding EntryBatch through the fn callback. Will
// retry failed attempts to retrieve ranges until the context is cancelled.
func (f *Fetcher) runWorker(ctx context.Context, ranges <-chan fetchRange, fn func(EntryBatch)) {
	for r := range ranges {
		// Logs MAY return fewer than the number of leaves requested. Only complete
		// if we actually got all the leaves we were expecting.
		for r.start <= r.end {
			// Fetcher.Run() can be cancelled while we are looping over this job.
			if err := ctx.Err(); err != nil {
				f.Log(fmt.Sprintf("Context closed: %v", err))
				return
			}
			resp, err := f.client.GetRawEntries(ctx, r.start, r.end)
			if err != nil {
				f.Log(fmt.Sprintf("GetRawEntries() failed: %v", err))
				// TODO(pavelkalinnikov): Introduce backoff policy and pause here.
				continue
			}
			fn(EntryBatch{Start: r.start, Entries: resp.Entries})
			r.start += int64(len(resp.Entries))
		}
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
