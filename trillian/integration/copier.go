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

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"

	ct "github.com/google/certificate-transparency-go"
)

// CopyChainGenerator creates certificate chains by copying suitable examples
// from a source log.
type CopyChainGenerator struct {
	start, limit             time.Time
	sourceRoots, targetRoots *x509util.PEMCertPool
	certs, precerts          chan []ct.ASN1Cert
}

// CopyChainOptions describes the parameters for a CopyChainGenerator instance.
type CopyChainOptions struct {
	// StartIndex indicates where to start scanning; negative value implies starting from a random position.
	StartIndex int64
	// BufSize is the number of buffered chains to hold.
	BufSize int
	// BatchSize indicates how many entries should be requested from the source log at a time.
	BatchSize int
	// ParallelFetch indicates how many parallel entry fetchers to run.
	ParallelFetch int
}

// NewCopyChainGenerator builds a certificate chain generator that sources
// chains from another source log, starting at startIndex (or a random index in
// the current tree size if startIndex is negative).  This function starts
// background goroutines that scan the log; cancelling the context will
// terminate these goroutines (after that the [Pre]CertChain() entrypoints will
// permanently fail).
func NewCopyChainGenerator(ctx context.Context, client *client.LogClient, cfg *configpb.LogConfig, startIndex int64, bufSize int) (ChainGenerator, error) {
	opts := CopyChainOptions{
		StartIndex:    startIndex,
		BufSize:       bufSize,
		BatchSize:     500,
		ParallelFetch: 2,
	}
	return NewCopyChainGeneratorFromOpts(ctx, client, cfg, opts)
}

// NewCopyChainGeneratorFromOpts builds a certificate chain generator that
// sources chains from another source log, starting at opts.StartIndex (or a
// random index in the current tree size if this is negative).  This function
// starts background goroutines that scan the log; cancelling the context will
// terminate these goroutines (after that the [Pre]CertChain() entrypoints
// will permanently fail).
func NewCopyChainGeneratorFromOpts(ctx context.Context, client *client.LogClient, cfg *configpb.LogConfig, opts CopyChainOptions) (ChainGenerator, error) {
	var start, limit time.Time
	var err error
	if cfg.NotAfterStart != nil {
		if err := cfg.NotAfterStart.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to parse NotAfterStart: %v", err)
		}
		start = cfg.NotAfterStart.AsTime()
	}
	if cfg.NotAfterLimit != nil {
		if err := cfg.NotAfterLimit.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to parse NotAfterLimit: %v", err)
		}
		limit = cfg.NotAfterLimit.AsTime()
	}

	targetPool := x509util.NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := targetPool.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots for target log: %v", err)
		}
	}
	if klog.V(4).Enabled() {
		for _, cert := range targetPool.RawCertificates() {
			klog.Infof("target root cert: %x Subject: %v", sha256.Sum256(cert.Raw), cert.Subject)
		}
	}

	seenOverlap := false
	srcRoots, err := client.GetAcceptedRoots(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted roots for source log: %v", err)
	}
	sourcePool := x509util.NewPEMCertPool()
	for _, root := range srcRoots {
		cert, err := x509.ParseCertificate(root.Data)
		if x509.IsFatal(err) {
			klog.Warningf("Failed to parse root certificate from source log: %v", err)
			continue
		}
		klog.V(4).Infof("source log root cert: %x Subject: %v", sha256.Sum256(cert.Raw), cert.Subject)
		sourcePool.AddCert(cert)
		if targetPool.Included(cert) {
			klog.V(3).Infof("source log root cert is accepted by target: %x Subject: %v", sha256.Sum256(cert.Raw), cert.Subject)
			seenOverlap = true
		}
	}
	if !seenOverlap {
		return nil, fmt.Errorf("failed to find any overlap in accepted roots for target %s", cfg.Prefix)
	}

	startIndex := opts.StartIndex
	if startIndex < 0 {
		// Pick a random start point in the source log's tree.
		sth, err := client.GetSTH(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get STH for source log: %v", err)
		}
		startIndex = rand.Int63n(int64(sth.TreeSize))
		klog.Infof("starting CopyChainGenerator from index %d (of %d) in source log", startIndex, sth.TreeSize)
	}

	generator := &CopyChainGenerator{
		start:       start,
		limit:       limit,
		targetRoots: targetPool,
		sourceRoots: sourcePool,
		certs:       make(chan []ct.ASN1Cert, opts.BufSize),
		precerts:    make(chan []ct.ASN1Cert, opts.BufSize),
	}

	// Start two goroutines to scan the source log for certs and precerts respectively.
	fetchOpts := scanner.FetcherOptions{
		BatchSize:     opts.BatchSize,
		ParallelFetch: opts.ParallelFetch,
		Continuous:    true,
		StartIndex:    startIndex,
	}
	certFetcher := scanner.NewFetcher(client, &fetchOpts)
	go certFetcher.Run(ctx, func(batch scanner.EntryBatch) {
		generator.processBatch(batch, generator.certs, ct.X509LogEntryType)
	})

	precertFetcher := scanner.NewFetcher(client, &fetchOpts)
	go precertFetcher.Run(ctx, func(batch scanner.EntryBatch) {
		generator.processBatch(batch, generator.precerts, ct.PrecertLogEntryType)
	})

	return generator, nil
}

// processBatch extracts chains of the desired type from a batch of entries and sends
// them down the channel.  May block on the channel consumer.
func (g *CopyChainGenerator) processBatch(batch scanner.EntryBatch, chains chan []ct.ASN1Cert, eType ct.LogEntryType) {
	klog.V(2).Infof("processBatch(%d): examine batch [%d, %d)", eType, batch.Start, int(batch.Start)+len(batch.Entries))
	for i, entry := range batch.Entries {
		index := batch.Start + int64(i)
		entry, err := ct.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			klog.Errorf("processBatch(%d): failed to build raw log entry %d: %v", eType, index, err)
			continue
		}
		if entry.Leaf.TimestampedEntry.EntryType != eType {
			klog.V(4).Infof("skip entry %d as EntryType=%d not %d", index, entry.Leaf.TimestampedEntry.EntryType, eType)
			continue
		}
		root, err := x509.ParseCertificate(entry.Chain[len(entry.Chain)-1].Data)
		if err != nil {
			klog.V(3).Infof("skip entry %d as its root cannot be parsed to check accepted: %v", index, err)
			continue
		}
		if !g.targetRoots.Included(root) {
			klog.V(3).Infof("skip entry %d as its root is not accepted by target log", index)
			continue
		}
		if !g.start.IsZero() || !g.limit.IsZero() {
			// Target log has NotAfter boundaries, so we need to parse the leaf cert to check
			// whether it complies with them.
			cert, err := x509.ParseCertificate(entry.Cert.Data)
			if x509.IsFatal(err) {
				klog.V(3).Infof("skip entry %d as its leaf cannot be parsed to check NotAfter: %v", index, err)
				continue
			}
			if !g.start.IsZero() && cert.NotAfter.Before(g.start) {
				klog.V(3).Infof("skip entry %d as its NotAfter (%v) is before %v", index, cert.NotAfter, g.start)
				continue
			}
			if !g.limit.IsZero() && !cert.NotAfter.Before(g.limit) {
				klog.V(3).Infof("skip entry %d as its NotAfter (%v) is after %v", index, cert.NotAfter, g.limit)
				continue
			}
		}

		chain := make([]ct.ASN1Cert, len(entry.Chain)+1)
		chain[0] = entry.Cert
		copy(chain[1:], entry.Chain)
		chains <- chain
	}
}

// CertChain returns a new cert chain taken from the source log.
// This may block until a suitable cert has been discovered in the source log.
func (g *CopyChainGenerator) CertChain() ([]ct.ASN1Cert, error) {
	chain := <-g.certs
	if len(chain) == 0 {
		return nil, errors.New("no certs available")
	}
	return chain, nil
}

// PreCertChain returns a new precert chain taken from the source log.
// This may block until a suitable precert has been discovered in the source log.
func (g *CopyChainGenerator) PreCertChain() ([]ct.ASN1Cert, []byte, error) {
	prechain := <-g.precerts
	if len(prechain) == 0 {
		return nil, nil, errors.New("no precerts available")
	}
	tbs, err := buildLeafTBS(prechain[0].Data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build leaf TBSCertificate: %v", err)
	}
	return prechain, tbs, nil
}
