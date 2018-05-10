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

// Package core provides transport-agnostic implementation of Migrillian tool.
package core

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian"
)

// Options holds configuration for a Controller.
type Options struct {
	scanner.FetcherOptions
	Submitters          int
	BatchesPerSubmitter int
}

// Controller coordinates migration from a CT log to a Trillian tree.
//
// TODO(pavelkalinnikov):
// - Add per-tree master election.
// - Coordinate multiple trees.
// - Schedule a distributed fetch to increase throughput.
// - Store CT STHs in Trillian or make this tool stateful on its own.
// - Make fetching stateful to reduce master resigning aftermath.
type Controller struct {
	opts    Options
	batches chan scanner.EntryBatch
}

// NewController creates a Controller configured by the passed in options.
func NewController(opts Options) *Controller {
	bufferSize := opts.Submitters * opts.BatchesPerSubmitter
	batches := make(chan scanner.EntryBatch, bufferSize)
	return &Controller{opts, batches}
}

// Run transfers CT log entries obtained via the CT log client to a Trillian
// log via the other client. If Options.Continuous is true then the migration
// process runs continuously trying to keep up with the target CT log.
func (c *Controller) Run(ctx context.Context, ctClient *client.LogClient, trClient *TrillianTreeClient) error {
	var wg sync.WaitGroup
	for w, cnt := 0, c.opts.Submitters; w < cnt; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runSubmitter(ctx, trClient)
		}()
	}
	defer func() {
		close(c.batches)
		wg.Wait()
	}()

	handler := func(b scanner.EntryBatch) {
		c.batches <- b
	}
	fetcher := scanner.NewFetcher(ctClient, &c.opts.FetcherOptions)
	return fetcher.Run(ctx, handler)
}

// runSubmitter obtaines CT log entry batches from the controller's channel and
// submits them through Trillian client. Returns when the channel is closed.
func (c *Controller) runSubmitter(ctx context.Context, tr *TrillianTreeClient) {
	for b := range c.batches {
		// TODO(pavelkalinnikov): Retry with backoff on errors.
		err := tr.addSequencedLeaves(ctx, &b)
		if c.opts.Quiet {
			continue
		}
		end := b.Start + int64(len(b.Entries))
		if err != nil {
			glog.Errorf("Failed to add batch [%d, %d): %v\n", b.Start, end, err)
		} else {
			glog.Infof("Added batch [%d, %d)\n", b.Start, end)
		}
	}
}

// TrillianTreeClient is a means of communicating with a Trillian log tree.
type TrillianTreeClient struct {
	Client    trillian.TrillianLogClient
	LogID     int64
	LogPrefix string
}

// addSequencedLeaves converts a batch of CT log entries into Trillian log
// leaves and submits them to Trillian via AddSequencedLeaves API.
func (c *TrillianTreeClient) addSequencedLeaves(ctx context.Context, b *scanner.EntryBatch) error {
	// TODO(pavelkalinnikov): Verify range inclusion against the remote STH.
	leaves := make([]*trillian.LogLeaf, len(b.Entries))
	for i, e := range b.Entries {
		var err error
		if leaves[i], err = buildLogLeaf(c.LogPrefix, b.Start+int64(i), &e); err != nil {
			return err
		}
	}

	req := trillian.AddSequencedLeavesRequest{LogId: c.LogID, Leaves: leaves}
	rsp, err := c.Client.AddSequencedLeaves(ctx, &req)
	if err != nil {
		return fmt.Errorf("AddSequencedLeaves(): %v", err)
	} else if rsp == nil {
		return errors.New("missing AddSequencedLeaves response")
	}
	// TODO(pavelkalinnikov): Check rsp.Results statuses.
	return nil
}
