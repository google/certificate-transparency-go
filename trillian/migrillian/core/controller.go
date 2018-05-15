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
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian/merkle"
	_ "github.com/google/trillian/merkle/rfc6962" // Register hasher.
	"github.com/google/trillian/types"
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
	opts     Options
	batches  chan scanner.EntryBatch
	ctClient *client.LogClient
	trClient *TrillianTreeClient
}

// NewController creates a Controller configured by the passed in options.
func NewController(opts Options, ctClient *client.LogClient, trClient *TrillianTreeClient) *Controller {
	bufferSize := opts.Submitters * opts.BatchesPerSubmitter
	batches := make(chan scanner.EntryBatch, bufferSize)
	return &Controller{opts: opts, batches: batches, ctClient: ctClient, trClient: trClient}
}

// Run transfers CT log entries obtained via the CT log client to a Trillian
// log via the other client. If Options.Continuous is true then the migration
// process runs continuously trying to keep up with the target CT log.
func (c *Controller) Run(ctx context.Context) error {
	root, err := c.trClient.getVerifiedRoot(ctx)
	if err != nil {
		return err
	}
	if c.opts.Continuous { // Ignore range parameters in Continuous mode.
		// TODO(pavelkalinnikov): Restore fetching state from storage in a better
		// way than "take the current tree size".
		c.opts.StartIndex, c.opts.EndIndex = int64(root.TreeSize), 0
		glog.Warningf("Tree %d: updated entry range to [%d, INF)",
			c.trClient.tree.TreeId, c.opts.StartIndex)
	}

	fetcher := scanner.NewFetcher(c.ctClient, &c.opts.FetcherOptions)
	sth, err := fetcher.Prepare(ctx)
	// TODO(pavelkalinnikov): Verify STH (should happen behind the scenes if
	// using the PublicKey option in LogClient).
	if err != nil {
		return err
	}
	if err := c.verifyConsistency(ctx, root, sth); err != nil {
		return err
	}

	var wg sync.WaitGroup
	for w, cnt := 0, c.opts.Submitters; w < cnt; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runSubmitter(ctx)
		}()
	}
	defer func() {
		close(c.batches)
		wg.Wait()
	}()

	handler := func(b scanner.EntryBatch) {
		c.batches <- b
	}
	return fetcher.Run(ctx, handler)
}

// verifyConsistency checks that the provided verified Trillian root is
// consistent with the CT log's STH.
func (c *Controller) verifyConsistency(ctx context.Context, root *types.LogRootV1, sth *ct.SignedTreeHead) error {
	h := c.trClient.verif.Hasher
	if root.TreeSize == 0 {
		if bytes.Equal(root.RootHash, h.EmptyRoot()) {
			return nil
		}
		return errors.New("invalid empty tree")
	}

	resp, err := c.ctClient.GetEntryAndProof(ctx, root.TreeSize-1, sth.TreeSize)
	if err != nil {
		return err
	}
	leafHash, err := h.HashLeaf(resp.LeafInput)
	if err != nil {
		return err
	}

	hash, err := merkle.NewLogVerifier(h).VerifiedPrefixHashFromInclusionProof(
		int64(root.TreeSize), int64(sth.TreeSize),
		resp.AuditPath, sth.SHA256RootHash[:], leafHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, root.RootHash) {
		return errors.New("inconsistent root")
	}
	return nil
}

// runSubmitter obtaines CT log entry batches from the controller's channel and
// submits them through Trillian client. Returns when the channel is closed.
func (c *Controller) runSubmitter(ctx context.Context) {
	for b := range c.batches {
		end := b.Start + int64(len(b.Entries))
		// TODO(pavelkalinnikov): Retry with backoff on errors.
		if err := c.trClient.addSequencedLeaves(ctx, &b); err != nil {
			glog.Errorf("Failed to add batch [%d, %d): %v\n", b.Start, end, err)
		} else {
			glog.Infof("Added batch [%d, %d)\n", b.Start, end)
		}
	}
}
