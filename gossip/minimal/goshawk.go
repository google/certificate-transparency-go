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

package minimal

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/gossip/minimal/configpb"
	"github.com/google/certificate-transparency-go/gossip/minimal/x509ext"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"

	logclient "github.com/google/certificate-transparency-go/client"
)

// Goshawk is an agent that retrieves STHs from a Gossip Hub, either in
// the form of synthetic certificates or more directly as signed blobs. Each
// STH is then checked for consistency against the source log.
type Goshawk struct {
	dests     map[string]*hubScanner // name => scanner
	origins   map[string]*originLog  // URL => log
	fetchOpts scanner.FetcherOptions
}

type originLog struct {
	logConfig

	sths       chan *x509ext.LogSTHInfo
	mu         sync.RWMutex
	currentSTH *ct.SignedTreeHead
}

type hubScanner struct {
	hawk        *Goshawk
	Name        string
	URL         string
	StartIndex  int64
	MinInterval time.Duration
	// TODO(drysdale): implement Goshawk for a true Gossip Hub.
	Log *logclient.LogClient
}

// NewGoshawkFromFile creates a Goshawk from the given filename, which should
// contain text-protobuf encoded configuration data, together with an optional
// http Client.
func NewGoshawkFromFile(ctx context.Context, filename string, hc *http.Client, fetchOpts scanner.FetcherOptions) (*Goshawk, error) {
	cfgText, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfgProto configpb.GoshawkConfig
	if err := proto.UnmarshalText(string(cfgText), &cfgProto); err != nil {
		return nil, fmt.Errorf("%s: failed to parse gossip config: %v", filename, err)
	}
	cfg, err := NewGoshawk(ctx, &cfgProto, hc, fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("%s: config error: %v", filename, err)
	}
	return cfg, nil
}

// NewGoshawk creates a gossiper from the given configuration protobuf and optional http client.
func NewGoshawk(ctx context.Context, cfg *configpb.GoshawkConfig, hc *http.Client, fetchOpts scanner.FetcherOptions) (*Goshawk, error) {
	if len(cfg.DestHub) == 0 {
		return nil, errors.New("no destination hub config found")
	}
	if len(cfg.SourceLog) == 0 {
		return nil, errors.New("no source log config found")
	}
	if cfg.BufferSize < 0 {
		return nil, fmt.Errorf("negative STH buffer size (%d) specified", cfg.BufferSize)
	}

	fetchOpts.Continuous = true
	hawk := Goshawk{
		dests:     make(map[string]*hubScanner),
		origins:   make(map[string]*originLog),
		fetchOpts: fetchOpts,
	}

	for _, destHub := range cfg.DestHub {
		dest, err := hubScannerFromProto(destHub, hc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dest hub config: %v", err)
		}
		if _, exists := hawk.dests[dest.Name]; exists {
			return nil, fmt.Errorf("duplicate dest hubs for name %q", dest.Name)
		}
		glog.Infof("configured dest Hub %s to scan at %s (%+v)", dest.Name, dest.URL, dest)
		dest.hawk = &hawk
		hawk.dests[dest.Name] = dest
	}
	seenNames := make(map[string]bool)
	for _, lc := range cfg.SourceLog {
		base, err := logConfigFromProto(lc, hc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse source log config: %v", err)
		}
		if _, exists := seenNames[base.Name]; exists {
			return nil, fmt.Errorf("duplicate source logs for name %s", base.Name)
		}
		seenNames[base.Name] = true

		if _, exists := hawk.origins[base.URL]; exists {
			return nil, fmt.Errorf("duplicate source logs for url %s", base.URL)
		}
		glog.Infof("configured source log %s at %s (%+v)", base.Name, base.URL, base)
		hawk.origins[base.URL] = &originLog{
			logConfig: *base,
			sths:      make(chan *x509ext.LogSTHInfo, cfg.BufferSize),
		}
	}
	return &hawk, nil
}

// Fly starts a collection of goroutines to perform log scanning and STH
// consistency checking. It should be terminated by cancelling the passed-in
// context.
func (hawk *Goshawk) Fly(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(hawk.dests) + len(hawk.origins))

	// If a Scanner fails, cancel everything else.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, dest := range hawk.dests {
		go func(dest *hubScanner) {
			defer wg.Done()
			glog.Infof("starting Scanner(%s)", dest.Name)
			err := dest.Scanner(ctx, hawk.fetchOpts)
			cancel()
			glog.Infof("finished Scanner(%s): %v", dest.Name, err)
		}(dest)
	}
	for _, origin := range hawk.origins {
		go func(origin *originLog) {
			defer wg.Done()
			glog.Infof("starting STHRetriever(%s)", origin.Name)
			origin.STHRetriever(cctx)
			glog.Infof("finished STHRetriever(%s)", origin.Name)
		}(origin)
	}

	// The Checkers are consumers at the end of a chain of channels and goroutines,
	// so they need to shut down last to prevent the producers getting blocked.
	var checkerWG sync.WaitGroup
	checkerWG.Add(len(hawk.origins))
	for _, origin := range hawk.origins {
		go func(origin *originLog) {
			defer checkerWG.Done()
			glog.Infof("starting Checker(%s)", origin.Name)
			origin.Checker(ctx)
			glog.Infof("finished Checker(%s)", origin.Name)
		}(origin)
	}

	wg.Wait()
	glog.Info("Scanner and STHRetrievers finished, now terminate Checkers")
	for _, origin := range hawk.origins {
		close(origin.sths)
	}
	checkerWG.Wait()
	glog.Info("Checkers finished")
}

// Scanner runs a continuous scan of the destination hub.
func (dest *hubScanner) Scanner(ctx context.Context, fetchOpts scanner.FetcherOptions) error {
	fetchOpts.StartIndex = dest.StartIndex
	fetcher := scanner.NewFetcher(dest.Log, &fetchOpts)
	return fetcher.Run(ctx, func(batch scanner.EntryBatch) {
		glog.V(2).Infof("Scanner(%s): examine batch [%d, %d)", dest.Name, batch.Start, int(batch.Start)+len(batch.Entries))
		for i, entry := range batch.Entries {
			index := batch.Start + int64(i)
			rawLogEntry, err := ct.RawLogEntryFromLeaf(index, &entry)
			if err != nil || rawLogEntry == nil {
				glog.Errorf("Scanner(%s): failed to build raw log entry %d: %v", dest.Name, index, err)
				continue
			}
			if rawLogEntry.Leaf.TimestampedEntry.EntryType != ct.X509LogEntryType {
				continue
			}
			dest.foundCert(rawLogEntry)
		}
	})
}

func (dest *hubScanner) foundCert(rawEntry *ct.RawLogEntry) {
	entry, err := rawEntry.ToLogEntry()
	if x509.IsFatal(err) {
		glog.Errorf("Scanner(%s): failed to parse cert from entry at %d: %v", dest.Name, rawEntry.Index, err)
		return
	}
	if entry.X509Cert == nil {
		glog.Errorf("Internal error: no X509Cert entry in %+v", entry)
		return
	}

	sthInfo, err := x509ext.LogSTHInfoFromCert(entry.X509Cert)
	if err != nil {
		return
	}
	url := string(sthInfo.LogURL)
	glog.Infof("Scanner(%s): process STHInfo for %s at index %d", dest.Name, url, entry.Index)

	// Consult the owning Goshawk instance to find the channel that this STH should go down.
	origin, ok := dest.hawk.origins[url]
	if !ok {
		glog.Warningf("Scanner(%s): found STH info for unrecognized log at %q in entry at %d", dest.Name, url, entry.Index)
		return
	}
	origin.sths <- sthInfo
}

// Checker processes retrieved STH information, checking against the source log
// (as long is has been long enough since the last check).
func (o *originLog) Checker(ctx context.Context) {
	var lastCheck time.Time
	for sthInfo := range o.sths {
		glog.Infof("Checker(%s): check STH size=%d timestamp=%d", o.Name, sthInfo.TreeSize, sthInfo.Timestamp)
		interval := time.Since(lastCheck)
		if interval < o.MinInterval {
			glog.Infof("Checker(%s): skip validation as too soon (%v) since last check (%v)", o.Name, interval, lastCheck)
			continue
		}
		lastCheck = time.Now()
		if err := o.validateSTH(ctx, sthInfo); err != nil {
			glog.Errorf("Checker(%s): failed to validate STH: %v", o.Name, err)
		}
	}
}

func (o *originLog) validateSTH(ctx context.Context, sthInfo *x509ext.LogSTHInfo) error {
	// Validate the signature in sthInfo
	sth := ct.SignedTreeHead{
		Version:           ct.Version(sthInfo.Version),
		TreeSize:          sthInfo.TreeSize,
		Timestamp:         sthInfo.Timestamp,
		SHA256RootHash:    sthInfo.SHA256RootHash,
		TreeHeadSignature: sthInfo.TreeHeadSignature,
	}
	if err := o.Log.VerifySTHSignature(sth); err != nil {
		return fmt.Errorf("Checker(%s): failed to validate STH signature: %v", o.Name, err)
	}

	currentSTH := o.getLastSTH()
	if currentSTH == nil {
		glog.Warningf("Checker(%s): no current STH available", o.Name)
		return nil
	}
	first, second := sthInfo.TreeSize, currentSTH.TreeSize
	firstHash, secondHash := sthInfo.SHA256RootHash[:], currentSTH.SHA256RootHash[:]
	if first > second {
		glog.Warningf("Checker(%s): retrieved STH info (size=%d) > current STH (size=%d); reversing check", o.Name, first, second)
		first, second = second, first
		firstHash, secondHash = secondHash, firstHash
	}
	proof, err := o.Log.GetSTHConsistency(ctx, first, second)
	if err != nil {
		return err
	}

	verifier := merkle.NewLogVerifier(rfc6962.DefaultHasher)
	if err := verifier.VerifyConsistencyProof(int64(first), int64(second), firstHash, secondHash, proof); err != nil {
		return fmt.Errorf("Failed to VerifyConsistencyProof(%x @size=%d, %x @size=%d): %v", firstHash, first, secondHash, second, err)
	}
	glog.Infof("Checker(%s): verified that hash %x @%d + proof = hash %x @%d\n", o.Name, firstHash, first, secondHash, second)
	return nil
}

func (o *originLog) STHRetriever(ctx context.Context) {
	ticker := time.NewTicker(o.MinInterval)
	for {
		sth, err := o.Log.GetSTH(ctx)
		if err != nil {
			glog.Errorf("STHRetriever(%s): failed to get-sth: %v", o.Name, err)
		} else {
			o.updateSTH(sth)
		}

		// Wait before retrieving another STH.
		glog.V(2).Infof("STHRetriever(%s): wait for a %s tick", o.Name, o.MinInterval)
		select {
		case <-ctx.Done():
			glog.Infof("STHRetriever(%s): termination requested", o.Name)
			return
		case <-ticker.C:
		}
	}
}

func (o *originLog) updateSTH(sth *ct.SignedTreeHead) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.currentSTH == nil || sth.TreeSize > o.currentSTH.TreeSize {
		glog.V(1).Infof("STHRetriever(%s): update tip STH to size=%d timestamp=%d", o.Name, sth.TreeSize, sth.Timestamp)
		o.currentSTH = sth
	}
}

func (o *originLog) getLastSTH() *ct.SignedTreeHead {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.currentSTH
}
