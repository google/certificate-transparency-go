// Copyright 2018 Google LLC. All Rights Reserved.
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
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"k8s.io/klog/v2"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/util/clock"
	"github.com/google/trillian/util/election2"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	metrics     treeMetrics
	metricsOnce sync.Once
)

// treeMetrics holds metrics keyed by Tree ID.
type treeMetrics struct {
	masterRuns       monitoring.Counter
	masterCancels    monitoring.Counter
	controllerStarts monitoring.Counter
	isMaster         monitoring.Gauge
	entriesFetched   monitoring.Counter
	entriesSeen      monitoring.Counter
	entriesStored    monitoring.Counter
	sthTimestamp     monitoring.Gauge
	sthTreeSize      monitoring.Gauge
}

// initMetrics creates metrics using the factory, if not yet created.
func initMetrics(mf monitoring.MetricFactory) {
	const treeID = "tree_id"
	metricsOnce.Do(func() {
		metrics = treeMetrics{
			masterRuns:       mf.NewCounter("master_runs", "Number of mastership runs.", treeID),
			masterCancels:    mf.NewCounter("master_cancels", "Number of unexpected mastership cancelations.", treeID),
			controllerStarts: mf.NewCounter("controller_starts", "Number of Controller (re-)starts.", treeID),
			isMaster:         mf.NewGauge("is_master", "The instance is currently the master.", treeID),
			entriesFetched:   mf.NewCounter("entries_fetched", "Entries fetched from the source log.", treeID),
			entriesSeen:      mf.NewCounter("entries_seen", "Entries seen by the submitters.", treeID),
			entriesStored:    mf.NewCounter("entries_stored", "Entries successfully submitted to Trillian.", treeID),
			sthTimestamp:     mf.NewGauge("sth_timestamp", "Timestamp of the last seen STH.", treeID),
			sthTreeSize:      mf.NewGauge("sth_tree_size", "Tree size of the last seen STH.", treeID),
		}
	})
}

// Options holds configuration for a Controller.
type Options struct {
	scanner.FetcherOptions
	Submitters         int
	ChannelSize        int
	NoConsistencyCheck bool
	StartDelay         time.Duration
	StopAfter          time.Duration
}

// OptionsFromConfig returns Options created from the passed in config.
func OptionsFromConfig(cfg *configpb.MigrationConfig) Options {
	opts := Options{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     int(cfg.BatchSize),
			ParallelFetch: int(cfg.NumFetchers),
			StartIndex:    cfg.StartIndex,
			EndIndex:      cfg.EndIndex,
			Continuous:    cfg.IsContinuous,
		},
		Submitters:         int(cfg.NumSubmitters),
		ChannelSize:        int(cfg.ChannelSize),
		NoConsistencyCheck: cfg.NoConsistencyCheck,
	}
	if cfg.NumFetchers == 0 {
		opts.ParallelFetch = 1
	}
	if cfg.NumSubmitters == 0 {
		opts.Submitters = 1
	}
	return opts
}

// Controller coordinates migration from a CT log to a Trillian tree.
type Controller struct {
	opts     Options
	ctClient *client.LogClient
	plClient *PreorderedLogClient
	ef       election2.Factory
	label    string
}

// NewController creates a Controller configured by the passed in options, CT
// and Trillian clients, and a master election factory.
//
// The passed in MetricFactory is used to create per-tree metrics, and it
// should be the same for all instances. However, it is used only once.
func NewController(
	opts Options,
	ctClient *client.LogClient,
	plClient *PreorderedLogClient,
	ef election2.Factory,
	mf monitoring.MetricFactory,
) *Controller {
	initMetrics(mf)
	l := strconv.FormatInt(plClient.treeID, 10)
	return &Controller{opts: opts, ctClient: ctClient, plClient: plClient, ef: ef, label: l}
}

// RunWhenMasterWithRestarts calls RunWhenMaster, and, if the migration is
// configured with continuous mode, restarts it whenever it returns.
func (c *Controller) RunWhenMasterWithRestarts(ctx context.Context) {
	uri := c.ctClient.BaseURI()
	treeID := c.plClient.treeID
	for run := true; run; run = c.opts.Continuous && ctx.Err() == nil {
		klog.Infof("Starting migration Controller (%d<-%q)", treeID, uri)
		if err := c.RunWhenMaster(ctx); err != nil {
			klog.Errorf("Controller.RunWhenMaster(%d<-%q): %v", treeID, uri, err)
			continue
		}
		klog.Infof("Controller stopped (%d<-%q)", treeID, uri)
	}
}

// RunWhenMaster is a master-elected version of Run method. It executes Run
// whenever this instance captures mastership of the tree ID. As soon as the
// instance stops being the master, Run is canceled. The method returns if a
// severe error occurs, the passed in context is canceled, or fetching is
// completed (in non-Continuous mode). Releases mastership when terminates.
func (c *Controller) RunWhenMaster(ctx context.Context) error {
	// Avoid thundering herd when starting multiple tasks on the same tree.
	if err := sleepRandom(ctx, 0, c.opts.StartDelay); err != nil {
		return err // The context has been canceled.
	}

	el, err := c.ef.NewElection(ctx, c.label)
	if err != nil {
		return err
	}
	metrics.isMaster.Set(0, c.label)
	defer func(ctx context.Context) {
		metrics.isMaster.Set(0, c.label)
		if err := el.Close(ctx); err != nil {
			klog.Warningf("%s: Election.Close(): %v", c.label, err)
		}
	}(ctx)

	for {
		if err := el.Await(ctx); err != nil {
			return err
		}
		metrics.isMaster.Set(1, c.label)

		mctx, err := el.WithMastership(ctx)
		if err != nil {
			return err
		} else if err := mctx.Err(); err != nil {
			return err
		}

		klog.Infof("%s: running as master", c.label)
		metrics.masterRuns.Inc(c.label)

		// Run while still master (or until an error).
		err = c.runWithRestarts(mctx)
		if ctx.Err() != nil {
			// We have been externally canceled, so return the current error (which
			// could be nil or a cancelation-related error).
			return err
		} else if mctx.Err() == nil {
			// We are still the master, so try to resign and emit the real error.
			if rerr := el.Resign(ctx); rerr != nil {
				klog.Errorf("%s: Election.Resign(): %v", c.label, rerr)
			}
			return err
		}

		// Otherwise the mastership has been canceled, retry.
		metrics.isMaster.Set(0, c.label)
		metrics.masterCancels.Inc(c.label)
	}
}

// runWithRestarts calls Run until it succeeds or the context is done, in
// continuous mode. For non-continuous mode it is simply equivalent to Run.
func (c *Controller) runWithRestarts(ctx context.Context) error {
	err := c.Run(ctx)
	if !c.opts.Continuous {
		return err
	}
	for err != nil && ctx.Err() == nil {
		klog.Errorf("%s: Controller.Run: %v", c.label, err)
		sleepRandom(ctx, 0, c.opts.StartDelay)
		err = c.Run(ctx)
	}
	return ctx.Err()
}

// Run transfers CT log entries obtained via the CT log client to a Trillian
// pre-ordered log via Trillian client. If Options.Continuous is true then the
// migration process runs continuously trying to keep up with the target CT
// log. Returns if an error occurs, the context is canceled, or all the entries
// have been transferred (in non-Continuous mode).
func (c *Controller) Run(ctx context.Context) error {
	metrics.controllerStarts.Inc(c.label)
	stopAfter := randDuration(c.opts.StopAfter, c.opts.StopAfter)
	start := time.Now()

	// Note: Non-continuous runs are not affected by StopAfter.
	pos, err := c.fetchTail(ctx, 0)
	if err != nil {
		return err
	}
	if !c.opts.Continuous {
		return nil
	}

	for stopAfter == 0 || time.Since(start) < stopAfter {
		// TODO(pavelkalinnikov): Integrate runWithRestarts here.
		next, err := c.fetchTail(ctx, pos)
		if err != nil {
			return err
		}
		if next == pos {
			// TODO(pavelkalinnikov): Pause with accordance to the rate of growth.
			// TODO(pavelkalinnikov): Make the duration configurable.
			if err := clock.SleepContext(ctx, 30*time.Second); err != nil {
				return err
			}
		}
		pos = next
	}

	return nil
}

// fetchTail transfers entries within the range specified in FetcherConfig,
// with respect to the passed in minimal position to start from, and the
// current tree size obtained from an STH.
func (c *Controller) fetchTail(ctx context.Context, begin uint64) (uint64, error) {
	treeSize, rootHash, err := c.plClient.getRoot(ctx)
	if err != nil {
		return 0, err
	}

	fo := c.opts.FetcherOptions
	if fo.Continuous { // Ignore range parameters in continuous mode.
		fo.StartIndex, fo.EndIndex = int64(treeSize), 0
		// Use non-continuous Fetcher, as we implement continuity in Controller.
		// TODO(pavelkalinnikov): Don't overload Fetcher's Continuous flag.
		fo.Continuous = false
	} else if fo.StartIndex < 0 {
		fo.StartIndex = int64(treeSize)
	}
	if int64(begin) > fo.StartIndex {
		fo.StartIndex = int64(begin)
	}
	klog.Infof("%s: fetching range [%d, %d)", c.label, fo.StartIndex, fo.EndIndex)

	fetcher := scanner.NewFetcher(c.ctClient, &fo)
	sth, err := fetcher.Prepare(ctx)
	if err != nil {
		return 0, err
	}
	metrics.sthTimestamp.Set(float64(sth.Timestamp), c.label)
	metrics.sthTreeSize.Set(float64(sth.TreeSize), c.label)
	if sth.TreeSize <= begin {
		return begin, nil
	}

	if err := c.verifyConsistency(ctx, treeSize, rootHash, sth); err != nil {
		return 0, err
	}

	var wg sync.WaitGroup
	batches := make(chan scanner.EntryBatch, c.opts.ChannelSize)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for w, cnt := 0, c.opts.Submitters; w < cnt; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.runSubmitter(cctx, batches); err != nil {
				klog.Errorf("%s: Stopping due to submitter error: %v", c.label, err)
				cancel() // Stop the other submitters and the Fetcher.
			}
		}()
	}

	handler := func(b scanner.EntryBatch) {
		metrics.entriesFetched.Add(float64(len(b.Entries)), c.label)
		select {
		case batches <- b:
		case <-cctx.Done(): // Avoid deadlock when shutting down.
		}
	}

	err = fetcher.Run(cctx, handler)
	close(batches)
	wg.Wait()
	if err != nil {
		return 0, err
	}
	// Run may have returned nil despite a cancel() call.
	if err := cctx.Err(); err != nil {
		return 0, fmt.Errorf("failed to fetch and submit the entire tail: %v", err)
	}
	return sth.TreeSize, nil
}

// verifyConsistency checks that the provided verified Trillian root is
// consistent with the CT log's STH.
func (c *Controller) verifyConsistency(ctx context.Context, treeSize uint64, rootHash []byte, sth *ct.SignedTreeHead) error {
	if treeSize == 0 {
		// Any head is consistent with empty root -- unnecessary to request empty proof.
		return nil
	}
	if c.opts.NoConsistencyCheck {
		klog.Warningf("%s: skipping consistency check", c.label)
		return nil
	}
	pf, err := c.ctClient.GetSTHConsistency(ctx, treeSize, sth.TreeSize)
	if err != nil {
		return err
	}
	return proof.VerifyConsistency(rfc6962.DefaultHasher, treeSize, sth.TreeSize,
		pf, rootHash, sth.SHA256RootHash[:])
}

// runSubmitter obtains CT log entry batches from the controller's channel and
// submits them through Trillian client. Returns when the channel is closed, or
// the client returns a non-recoverable error (an example of a recoverable
// error is when Trillian write quota is exceeded).
func (c *Controller) runSubmitter(ctx context.Context, batches <-chan scanner.EntryBatch) error {
	for b := range batches {
		entries := float64(len(b.Entries))
		metrics.entriesSeen.Add(entries, c.label)

		end := b.Start + int64(len(b.Entries))
		if err := c.plClient.addSequencedLeaves(ctx, &b); err != nil {
			// addSequencedLeaves failed to submit entries despite retries. At this
			// point there is not much we can do. Seemingly the best strategy is to
			// shut down the Controller.
			return fmt.Errorf("failed to add batch [%d, %d): %v", b.Start, end, err)
		}
		klog.Infof("%s: added batch [%d, %d)", c.label, b.Start, end)
		metrics.entriesStored.Add(entries, c.label)
	}
	return nil
}

// sleepRandom sleeps for random duration in [base, base+spread).
func sleepRandom(ctx context.Context, base, spread time.Duration) error {
	d := randDuration(base, spread)
	if d == 0 {
		return nil
	}
	return clock.SleepContext(ctx, d)
}

// randDuration returns a random duration in [base, base+spread).
func randDuration(base, spread time.Duration) time.Duration {
	d := base
	if spread != 0 {
		d += time.Duration(rand.Int63n(int64(spread)))
	}
	return d
}
