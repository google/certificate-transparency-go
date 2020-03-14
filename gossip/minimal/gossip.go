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

// Package minimal provides a minimal gossip implementation for CT which
// uses X.509 certificate extensions to hold gossiped STH values for logs.
// This allows STH values to be exchanged between participating logs without
// any changes to the log software (although participating logs will need
// to add additional trusted roots for the gossip sources).
package minimal

/// behaviours for: CT Log Submitter, Pure Hub Submitter, CT Source Log, Gossiper

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/monitoring"

	ct "github.com/google/certificate-transparency-go"
	logclient "github.com/google/certificate-transparency-go/client"
	hubclient "github.com/google/trillian-examples/gossip/client"
	"github.com/google/certificate-transparency-go/gossip"

	// Register PEMKeyFile ProtoHandler
	_ "github.com/google/trillian/crypto/keys/pem/proto"
)

var (
	once sync.Once

	// Per source-log (label "logname") metrics.
	knownSourceLogs          monitoring.Gauge   // logname => value (always 1.0)
	readsCounter             monitoring.Counter // logname => value
	readErrorsCounter        monitoring.Counter // logname => value
	lastSeenSTHTimestamp     monitoring.Gauge   // logname => value
	lastSeenSTHTreeSize      monitoring.Gauge   // logname => value
	lastRecordedSTHTimestamp monitoring.Gauge   // logname => value
	lastRecordedSTHTreeSize  monitoring.Gauge   // logname => value

	// Per destination hub (label "hubname") metrics.
	destPureHub        monitoring.Gauge   // hubname => value (0.0 or 1.0)
	writesCounter      monitoring.Counter // hubname => value
	writeErrorsCounter monitoring.Counter // hubname => value
)

// setupMetrics initializes all the exported metrics.
func setupMetrics(mf monitoring.MetricFactory) {
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	knownSourceLogs = mf.NewGauge("known_logs", "Set to 1 for known source logs", "logname")
	readsCounter = mf.NewCounter("log_reads", "Number of source log read requests", "logname")
	readErrorsCounter = mf.NewCounter("log_read_errors", "Number of source log read errors", "logname")
	lastSeenSTHTimestamp = mf.NewGauge("last_seen_sth_timestamp", "Time of last seen STH in ms since epoch", "logname")
	lastSeenSTHTreeSize = mf.NewGauge("last_seen_sth_treesize", "Size of tree at last seen STH", "logname")
	lastRecordedSTHTimestamp = mf.NewGauge("last_recorded_sth_timestamp", "Time of last recorded STH in ms since epoch", "logname")
	lastRecordedSTHTreeSize = mf.NewGauge("last_recorded_sth_treesize", "Size of tree at last recorded STH", "logname")

	destPureHub = mf.NewGauge("dest_pure_hub", "Set to  for known destination hubs", "hubname")
	writesCounter = mf.NewCounter("hub_writes", "Number of destination hub submissions", "hubname")
	writeErrorsCounter = mf.NewCounter("hub_write_errors", "Number of destination hub submission errors", "hubname")
}

/// ---------------------------------

type logConfig struct {
	Name        string
	URL         string
	Log         *logclient.LogClient
	MinInterval time.Duration
}

type monitorConfig struct {
	Name          string
	URL           string
	HttpClient *logclient.LogClient
	lastBroadcast map[string]time.Time
}

type hubSubmitter interface {
	CanSubmit(ctx context.Context, g *Gossiper) error
	SubmitSTH(ctx context.Context, srcName, srcURL string, sth *ct.SignedTreeHead, g *Gossiper) error
}

type destHub struct {
	Name              string
	URL               string
	Submitter         hubSubmitter
	MinInterval       time.Duration
	lastHubSubmission map[string]time.Time
}

/// ---------------------------------
/// CT Log Submitter Functions
/// ---------------------------------

// ctLogSubmitter is an implementation of hubSubmitter that submits to CT Logs
// that accepts STHs embedded in synthetic certificates.
type ctLogSubmitter struct {
	Log *logclient.LogClient
}

/// checks if gossiper roots match the log's roots
// CanSubmit checks whether the destination CT log includes the root certificate
// that we use for generating synthetic certificates.
func (c *ctLogSubmitter) CanSubmit(ctx context.Context, g *Gossiper) error {
	glog.V(1).Infof("Get accepted roots for destination CT log at %s", c.Log.BaseURI())
	roots, err := c.Log.GetAcceptedRoots(ctx)
	if err != nil {
		return fmt.Errorf("failed to get accepted roots: %v", err)
	}
	for _, root := range roots {
		if bytes.Equal(root.Data, g.root.Raw) {
			return nil
		}
	}
	return fmt.Errorf("gossip root not found in CT log at %s", c.Log.BaseURI())
}

/// 1. convert STH to "synthetic cert"
/// 2. add cert to logSubmitter's chain
// SubmitSTH submits the given STH for inclusion in the destination CT Log, in the
// form of a synthetic certificate.
func (c *ctLogSubmitter) SubmitSTH(ctx context.Context, name, url string, sth *ct.SignedTreeHead, g *Gossiper) error {
	var err error
	cert, err := g.CertForSTH(name, url, sth)
	if err != nil {
		return fmt.Errorf("synthetic cert generation failed: %v", err)
	}
	chain := []ct.ASN1Cert{*cert, {Data: g.root.Raw}}
	sct, err := c.Log.AddChain(ctx, chain)
	if err != nil {
		return fmt.Errorf("failed to AddChain(%s): %v", c.Log.BaseURI(), expandRspError(err))
	}
	glog.V(1).Infof("SCT from %s for STH(size=%d) from %s: {ts=%d, sig=%x} ", c.Log.BaseURI(), sth.TreeSize, name, sct.Timestamp, sct.Signature.Signature)
	return nil
}

func expandRspError(err error) string {
	if e, ok := err.(jsonclient.RspError); ok {
		return fmt.Sprintf("%d: %s (body: %s)", e.StatusCode, e.Err.Error(), e.Body)
	}
	return err.Error()
}

/// ---------------------------------
/// Pure Hub Submitter Functions
/// ---------------------------------

// pureHubSubmitter is an implementation of hubSubmitter that submits to
// Gossip Hubs.
type pureHubSubmitter struct {
	Hub *hubclient.HubClient
}

// CanSubmit checks whether the hub accepts the public keys of all of the
// source Logs.
func (p *pureHubSubmitter) CanSubmit(ctx context.Context, g *Gossiper) error {
	glog.V(1).Infof("Get accepted public keys for destination Gossip Hub at %s", p.Hub.BaseURI())
	keys, err := p.Hub.GetSourceKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to get source keys: %v", err)
	}

	for _, src := range g.srcs {
		verifier := src.Log.Verifier
		if verifier == nil {
			return fmt.Errorf("no verifier available for source log %q", src.Log.BaseURI())
		}
		if !hubclient.AcceptableSource(verifier.PubKey, keys) {
			return fmt.Errorf("source log %q is not accepted by the hub", src.Log.BaseURI())
		}
	}
	return nil
}

// SubmitSTH submits the given STH into the Gossip Hub.
func (p *pureHubSubmitter) SubmitSTH(ctx context.Context, name, url string, sth *ct.SignedTreeHead, g *Gossiper) error {
	sgt, err := p.Hub.AddCTSTH(ctx, url, sth)
	if err != nil {
		return fmt.Errorf("failed to AddCTSTH(%s): %v", p.Hub.BaseURI(), err)
	}
	glog.V(1).Infof("SGT from %s for STH(size=%d) from %s: {ts=%d, sig=%x} ", p.Hub.BaseURI(), sth.TreeSize, name, sgt.TimestampedEntry.HubTimestamp, sgt.HubSignature)
	return nil
}

type sourceLog struct {
	logConfig

	mu      sync.Mutex
	lastSTH *ct.SignedTreeHead
}

type monitor struct {
	monitorConfig
	mu sync.Mutex
}

/// ---------------------------------
/// Gossiper Functions
/// ---------------------------------

// Gossiper is an agent that retrieves STH values from a set of source logs and
// distributes it to a destination log in the form of an X.509 certificate with
// the STH value embedded in it.
type Gossiper struct {
	signer     crypto.Signer
	root       *x509.Certificate
	dests      map[string]*destHub
	srcs       map[string]*sourceLog
	monitors   map[string]*monitor
	bufferSize int
}

// CheckCanSubmit checks whether the gossiper can submit STHs to all destination hubs.
func (g *Gossiper) CheckCanSubmit(ctx context.Context) error {
	for _, d := range g.dests {
		if err := d.Submitter.CanSubmit(ctx, g); err != nil {
			return err
		}
	}
	return nil
}

/// 1. create channel for STHs
/// 2. add all source logs to gossiper waitgroup
/// 3. Periodically retreieve STH from each source log concurrently
/// 4. Submit any newly received STHs to a list of destinations
// Run starts a gossiper set of goroutines.  It should be terminated by cancelling
// the passed-in context.
func (g *Gossiper) Run(ctx context.Context) {
	sths := make(chan sthInfo, g.bufferSize)

	var wg sync.WaitGroup
	wg.Add(len(g.srcs))
	for _, src := range g.srcs {
		go func(src *sourceLog) {
			defer wg.Done()
			glog.Infof("starting Retriever(%s)", src.Name)
			src.Retriever(ctx, g, sths)
			glog.Infof("finished Retriever(%s)", src.Name)
		}(src)
	}
	go func(){
		glog.Info("starting Gossip Listener")
		g.Listen(ctx)
		glog.Info("finished Gossip Listener")
	} ()
	///////////////////////////////////
	// glog.Info("starting Submitter")
	// g.Submitter(ctx, sths)
	// glog.Info("finished Submitter")
	glog.Info("starting Gossip Broadcaster")
	g.Broadcast(ctx, sths)
	glog.Info("finished Gossip Broadcaster")

	// Drain the sthInfo channel during shutdown so the Retrievers don't block on it.
	go func() {
		for info := range sths {
			glog.V(1).Infof("discard STH from %s", info.name)
		}
	}()

	wg.Wait()
	close(sths)
}

func (g *Gossiper) Broadcast(ctx context.Context, s <-chan sthInfo) {
	for {
		select {
		case <-ctx.Done():
			glog.Info("Broadcast: termination requested")
			return
		case info := <-s:
			fromLog := info.name
			glog.V(1).Infof("Broadcast: Broadcasting(%s)", fromLog)
			src, ok := g.srcs[fromLog]
			if !ok {
				glog.Errorf("Broadcast: Broadcasting(%s) for unknown source log", fromLog)
			}

			/// TODO: broadcast STH and other info to each monitor
			for _, monitor := range g.monitors {
				glog.Infof("Broadcaster: info (%s)->(%s)", src.Name, monitor.Name)
				ack, err := monitor.HttpClient.PostGossipExchange(ctx, ct.GossipExchangeRequest{
					LogURL: src.URL,
					STH: *info.sth,
					IsConsistent: true,
					Proof: []ct.MerkleTreeNode{},
				})
				if err != nil{
					glog.Errorf("Broadcaster: Acknowledgement for %s failed. Error: %s", monitor.Name, err)
				}
				glog.Infof("Broadcaster: Retrieved Acknowledgement (%s)->(%s)\n%s", src.Name, monitor.Name, ack)
			}
		}
	}
}

func (g *Gossiper) Listen(ctx context.Context) {
	glog.Info("[Listen] Actually Starting Listener")
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(ct.GossipExchangePath, gossip.HandleGossipListener)
	server := &http.Server{
		/// This should build from config
		// Addr:    *listenAddress,
		Addr:    ":6966",
		Handler: serveMux,
	}
	glog.Info("Listen: Created Server")
	go func() {
		<-ctx.Done()
		glog.Info("Listen: termination requested")

		// We received an interrupt signal, shut down.
		if err := server.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			glog.V(1).Infof("Listen: Server Shutdown: %v", err)
		}
	}()

	glog.Info("Listen: Listen&Serve on :6966/ct/v1/gossip-exchange")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		glog.Fatalf("HTTP server ListenAndServe: %v", err)
	}
}

// Submitter periodically services the provided channel and submits the
// certificates received on it to the destination logs.
func (g *Gossiper) Submitter(ctx context.Context, s <-chan sthInfo) {
	for {
		select {
		case <-ctx.Done():
			glog.Info("Submitter: termination requested")
			return
		case info := <-s:
			fromLog := info.name
			/// what is add-chain?
			glog.V(1).Infof("Submitter: Add-chain(%s)", fromLog)
			src, ok := g.srcs[fromLog]
			if !ok {
				glog.Errorf("Submitter: AddChain(%s) for unknown source log", fromLog)
			}

			for _, dest := range g.dests {
				if interval := time.Since(dest.lastHubSubmission[fromLog]); interval < dest.MinInterval {
					glog.Warningf("Submitter: Add-chain(%s=>%s) skipped as only %v passed (< %v) since last submission", fromLog, dest.Name, interval, dest.MinInterval)
					continue
				}
				writesCounter.Inc(dest.Name)
				if err := dest.Submitter.SubmitSTH(ctx, src.Name, src.URL, info.sth, g); err != nil {
					glog.Errorf("Submitter: Add-chain(%s=>%s) failed: %v", fromLog, dest.Name, err)
					writeErrorsCounter.Inc(dest.Name)
				} else {
					glog.Infof("Submitter: Add-chain(%s=>%s) returned SCT", fromLog, dest.Name)
					dest.lastHubSubmission[fromLog] = time.Now()
				}

			}

		}
	}
}


type sthInfo struct {
	name    string
	sth     *ct.SignedTreeHead
	entries []ct.LogEntry
}

/// ---------------------------------
/// Source Log Functions
/// ---------------------------------

// Retriever periodically retrieves an STH from the source log, and if a new STH is
// available, writes it to the given channel.
func (src *sourceLog) Retriever(ctx context.Context, g *Gossiper, s chan<- sthInfo) {
	// Wait for a random interval so all Retrievers aren't in sync.
	jitterWait := time.Duration(rand.Int63n(int64(src.MinInterval)))
	glog.V(1).Infof("Retriever(%s): wait for %v before starting...", src.Name, jitterWait)
	waitChan := time.After(jitterWait)
	select {
	case <-ctx.Done():
		glog.Infof("Retriever(%s): termination requested", src.Name)
		return
	case <-waitChan:
		glog.V(1).Infof("Retriever(%s): wait for %v before starting...done", src.Name, jitterWait)
	}

	schedule.Every(ctx, src.MinInterval, func(ctx context.Context) {
		glog.V(1).Infof("Retriever(%s): Get STH", src.Name)
		readsCounter.Inc(src.Name)
		lastSTH := src.lastSTH

		sth, err := src.GetNewerSTH(ctx, g)
		if err != nil {
			glog.Errorf("Retriever(%s): failed to get STH: %v", src.Name, err)
			readErrorsCounter.Inc(src.Name)
		} else if sth != nil {
			entries, err := src.GetNewerEntries(ctx, g, lastSTH, sth)
			if err != nil {
				glog.Errorf("Retriever(%s): failed to NewerEntries STH: %v", src.Name, err)
			}
			if len(entries) > 0 {
				glog.V(1).Infof("Retriever(%s): newest entry (%v)", src.Name, entries[0])
			} else {
				glog.V(1).Infof("Retriever(%s): received (%v) new entries", src.Name, len(entries))
			}

			glog.V(1).Infof("Retriever(%s): pass on STH", src.Name)
			lastRecordedSTHTimestamp.Set(float64(sth.Timestamp), src.Name)
			lastRecordedSTHTreeSize.Set(float64(sth.TreeSize), src.Name)
			s <- sthInfo{name: src.Name, sth: sth, entries: entries}
		}
		glog.V(2).Infof("Retriever(%s): wait for a %s tick", src.Name, src.MinInterval)
	})
	glog.Infof("Retriever(%s): termination requested", src.Name)
}

// GetNewerSTH retrieves a current STH from the source log and (if it is new)
// returns it. May return nil, nil if no new STH is available.
func (src *sourceLog) GetNewerSTH(ctx context.Context, g *Gossiper) (*ct.SignedTreeHead, error) {
	glog.V(1).Infof("Get STH for source log %s", src.Name)
	sth, err := src.Log.GetSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get new STH: %v", err)
	}
	lastSeenSTHTimestamp.Set(float64(sth.Timestamp), src.Name)
	lastSeenSTHTreeSize.Set(float64(sth.TreeSize), src.Name)

	src.mu.Lock()
	defer src.mu.Unlock()
	if reflect.DeepEqual(sth, src.lastSTH) {
		glog.Infof("Retriever(%s): same STH as previous", src.Name)
		return nil, nil
	}
	src.lastSTH = sth
	glog.Infof("Retriever(%s): got STH size=%d timestamp=%d hash=%x", src.Name, sth.TreeSize, sth.Timestamp, sth.SHA256RootHash)
	return sth, nil
}

// GetNewerEntries retrieves [start_index, end_index] newest entries from the source log
// and returns new entries, as available
func (src *sourceLog) GetNewerEntries(ctx context.Context, g *Gossiper, lastSTH, newSTH *ct.SignedTreeHead) ([]ct.LogEntry, error) {
	newTreeSize := newSTH.TreeSize
	if newTreeSize <= 0 {
		return nil, fmt.Errorf("Logger has no certificates: newTreeSize is (%v)", lastSTH)
	}
	if lastSTH == nil {
		return nil, fmt.Errorf("Cannot get new entries: lastSTH is (%v)", lastSTH)
	}
	prevTreeSize := lastSTH.TreeSize
	glog.V(1).Infof("Retriever(%s): Previous Tree Size (%v)", src.Name, prevTreeSize)

	start_index, end_index := int64(prevTreeSize+1), int64(prevTreeSize+newTreeSize)
	glog.V(1).Infof("Get newer entries for source log %s from (%v) to (%v)", src.Name, start_index, end_index)
	entries, err := src.Log.GetEntries(ctx, start_index, end_index)
	if err != nil {
		return nil, fmt.Errorf("failed to get new entries: %v", err)
	}

	return entries, nil
}
