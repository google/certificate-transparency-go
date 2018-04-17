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
	"fmt"
	"log"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
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

	// Don't print any status messages to stdout.
	Quiet bool
}

// DefaultFetcherOptions returns new FetcherOptions with sensible defaults.
func DefaultFetcherOptions() *FetcherOptions {
	return &FetcherOptions{
		BatchSize:     1000,
		ParallelFetch: 1,
		StartIndex:    0,
		EndIndex:      0,
		Quiet:         false,
	}
}

// Fetcher is a tool that fetches entries from a CT Log.
type Fetcher struct {
	// Client used to talk to the CT log instance.
	cli *client.LogClient
	// Configuration options for this Fetcher instance.
	opts *FetcherOptions

	// Current STH of the Log this Fetcher sends queries to.
	sth *ct.SignedTreeHead

	// TODO(pavelkalinnikov): Consider log.Logger instead.
	Log func(msg string)
}

// EntryBatch represents a contiguous range of entries of the Log.
type EntryBatch struct {
	start   int64          // LeafIndex of the first entry in the range.
	entries []ct.LeafEntry // Entries of the range.
}

// fetchRange represents a range of certs to fetch from a CT log.
type fetchRange struct {
	start int64 // inclusive
	end   int64 // inclusive
}

// NewFetcher creates a Fetcher instance using client to talk to the log,
// taking configuration options from opts.
func NewFetcher(cli *client.LogClient, opts *FetcherOptions) *Fetcher {
	fetcher := &Fetcher{cli: cli, opts: opts}
	if opts.Quiet {
		fetcher.Log = func(msg string) {}
	} else {
		fetcher.Log = func(msg string) { log.Print(msg) }
	}
	return fetcher
}

// Prepare caches the latest Log's STH in the Fetcher and returns it. It also
// adjusts the entry range to fit the size of the tree.
func (f *Fetcher) Prepare(ctx context.Context) (*ct.SignedTreeHead, error) {
	sth, err := f.cli.GetSTH(ctx)
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
// context is cancelled. For each successfully fetched batch, pushes it to the
// out channel.
func (f *Fetcher) Run(ctx context.Context, out chan<- EntryBatch) error {
	f.Log("Starting up Fetcher...\n")

	if f.sth == nil {
		if _, err := f.Prepare(ctx); err != nil {
			return err
		}
	}

	jobs := f.genJobs(ctx)

	// Run fetcher workers.
	var wg sync.WaitGroup
	for w, cnt := 0, f.opts.ParallelFetch; w < cnt; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f.runWorker(ctx, jobs, out)
			f.Log(fmt.Sprintf("Fetcher worker %d finished", idx))
		}(w)
	}
	wg.Wait()

	return nil
}

// getJobs returns a channel of fetching jobs, each job is a Log entry range.
// Can be stopped using ctx.
func (f *Fetcher) genJobs(ctx context.Context) <-chan fetchRange {
	start, end := f.opts.StartIndex, f.opts.EndIndex
	batch := int64(f.opts.BatchSize)

	jobs := make(chan fetchRange)
	go func() {
		defer close(jobs)
		for start < end {
			batchEnd := min(start+batch, end)
			next := fetchRange{start, batchEnd - 1}
			select {
			case <-ctx.Done():
				f.Log(fmt.Sprintf("genJobs cancelled: %v", ctx.Err()))
				return
			case jobs <- next:
			}
			start = batchEnd
		}
	}()
	return jobs
}

// Worker function for fetcher jobs.
// Accepts cert ranges to fetch over the jobs channel, and if the fetch is
// successful sends the []entryInfo slice to the batches channel. Will retry
// failed attempts to retrieve ranges indefinitely.
func (f *Fetcher) runWorker(ctx context.Context, jobs <-chan fetchRange, out chan<- EntryBatch) {
	for r := range jobs {
		// Logs MAY return fewer than the number of leaves requested. Only complete
		// if we actually got all the leaves we were expecting.
		for r.start <= r.end {
			// Fetcher.Run() can be cancelled while we are looping over this job.
			if err := ctx.Err(); err != nil {
				f.Log(fmt.Sprintf("Context closed: %v", err))
				return
			}
			resp, err := f.cli.GetRawEntries(ctx, r.start, r.end)
			if err != nil {
				f.Log(fmt.Sprintf("GetRawEntries() failed: %v", err))
				continue
			}
			out <- EntryBatch{start: r.start, entries: resp.Entries}
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
