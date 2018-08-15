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
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/util/exepool"
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
}

// DefaultFetcherOptions returns new FetcherOptions with sensible defaults.
func DefaultFetcherOptions() *FetcherOptions {
	return &FetcherOptions{
		BatchSize:     1000,
		ParallelFetch: 1,
		StartIndex:    0,
		EndIndex:      0,
		Continuous:    false,
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
	return &Fetcher{client: client, opts: opts}
}

// Prepare caches the latest Log's STH if not present and returns it. It also
// adjusts the entry range to fit the size of the tree.
func (f *Fetcher) Prepare(ctx context.Context) (*ct.SignedTreeHead, error) {
	if f.sth != nil {
		return f.sth, nil
	}

	sth, err := f.client.GetSTH(ctx)
	if err != nil {
		glog.Errorf("GetSTH() failed: %v", err)
		return nil, err
	}
	glog.Infof("Got STH with %d certs", sth.TreeSize)

	if size := int64(sth.TreeSize); f.opts.EndIndex == 0 || f.opts.EndIndex > size {
		glog.Warningf("Reset EndIndex from %d to %d", f.opts.EndIndex, size)
		f.opts.EndIndex = size
	}
	f.sth = sth
	return sth, nil
}

// Run performs fetching of the Log. Blocks until scanning is complete or
// context is cancelled. For each successfully fetched batch, runs the fn
// callback. All fetching Jobs are run in the passed in execution Pool.
func (f *Fetcher) Run(ctx context.Context, xp *exepool.Pool, fn func(EntryBatch)) error {
	glog.V(1).Info("Starting up Fetcher...")
	if _, err := f.Prepare(ctx); err != nil {
		return err
	}

	xpc, err := xp.NewClient()
	if err != nil {
		return err
	}
	xpsc := exepool.NewSyncClient(xpc, f.opts.ParallelFetch)
	defer xpsc.Close()

	batch := int64(f.opts.BatchSize)
	for start, end := f.opts.StartIndex, f.opts.EndIndex; start < end; {
		batchEnd := start + min(end-start, batch)
		next := fetchRange{start, batchEnd - 1}

		job := exepool.Job(func() { f.runJob(ctx, next, fn) })
		if err := xpsc.Add(ctx, job); err != nil {
			return err
		}

		start = batchEnd
		if start == end && f.opts.Continuous {
			if err := f.updateSTH(ctx); err != nil {
				return err
			}
			end = f.opts.EndIndex
		}
	}

	glog.V(1).Info("Stopping Fetcher...")
	return nil
}

// updateSTH waits until a bigger STH is discovered, and updates the Fetcher
// accordingly. It is optimized for both bulk-load (new STH is way bigger then
// the last one) and keep-up (STH grows slowly) modes of operation. Waits for
// some time until the STH grows enough to request a full batch, but falls back
// to *any* STH bigger than the old one if it takes too long.
// Returns error only if the context is cancelled.
func (f *Fetcher) updateSTH(ctx context.Context) error {
	// TODO(pavelkalinnikov): Make these parameters tunable.
	const quickDur = 45 * time.Second
	if f.sthBackoff == nil {
		f.sthBackoff = &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}
	}

	lastSize := uint64(f.opts.EndIndex)
	targetSize := lastSize + uint64(f.opts.BatchSize)
	quickDeadline := time.Now().Add(quickDur)

	return f.sthBackoff.Retry(ctx, func() error {
		sth, err := f.client.GetSTH(ctx)
		if err != nil {
			return err
		}
		glog.V(2).Infof("Got STH with %d certs", sth.TreeSize)

		quick := time.Now().Before(quickDeadline)
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

// runJob fetches a cert range, and sends an EntryBatch through the fn callback
// (possibly multiple times if the source log returns smaller batches). Will
// retry failed attempts to retrieve ranges until the context is canceled.
func (f *Fetcher) runJob(ctx context.Context, r fetchRange, fn func(EntryBatch)) {
	// Logs MAY return fewer than the number of leaves requested. Only complete
	// if we actually got all the leaves we were expecting.
	for r.start <= r.end {
		// Context can be cancelled while we are looping over this job.
		if err := ctx.Err(); err != nil {
			glog.Warningf("Job %+v canceled: %v", r, err)
			return
		}
		resp, err := f.client.GetRawEntries(ctx, r.start, r.end)
		if err != nil {
			glog.Errorf("GetRawEntries(%+v) failed: %v", r, err)
			// TODO(pavelkalinnikov): Introduce backoff policy and pause here.
			continue
		}
		fn(EntryBatch{Start: r.start, Entries: resp.Entries})
		r.start += int64(len(resp.Entries))
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
