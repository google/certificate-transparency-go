// Copyright 2014 Google Inc. All Rights Reserved.
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

// Package scanner holds code for iterating through the contents of a CT log.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
)

// ScannerOptions holds configuration options for the Scanner.
type ScannerOptions struct { // nolint:golint
	FetcherOptions

	// Custom matcher for x509 Certificates, functor will be called for each
	// Certificate found during scanning. Should be a Matcher or LeafMatcher
	// implementation.
	Matcher interface{}

	// Match precerts only (Matcher still applies to precerts).
	PrecertOnly bool

	// Number of concurrent matchers to run.
	NumWorkers int

	// Number of fetched entries to buffer on their way to the callbacks.
	BufferSize int
}

// DefaultScannerOptions returns a new ScannerOptions with sensible defaults.
func DefaultScannerOptions() *ScannerOptions {
	return &ScannerOptions{
		FetcherOptions: *DefaultFetcherOptions(),
		Matcher:        &MatchAll{},
		PrecertOnly:    false,
		NumWorkers:     1,
	}
}

// Scanner is a tool to scan all the entries in a CT Log.
type Scanner struct {
	fetcher *Fetcher

	// Configuration options for this Scanner instance
	opts ScannerOptions

	// Counters of the number of certificates scanned and matched
	certsProcessed int64
	certsMatched   int64

	// Counter of the number of precertificates encountered during the scan.
	precertsSeen int64

	unparsableEntries         int64
	entriesWithNonFatalErrors int64

	Log func(msg string)
}

// entryInfo represents information about a log entry.
type entryInfo struct {
	// The index of the entry containing the LeafInput in the log.
	index int64
	// The log entry returned by the log server.
	entry ct.LeafEntry
}

// Takes the error returned by either x509.ParseCertificate() or
// x509.ParseTBSCertificate() and determines if it's non-fatal or otherwise.
// In the case of non-fatal errors, the error will be logged,
// entriesWithNonFatalErrors will be incremented, and the return value will be
// false.
// Fatal errors will cause the function to return true.
// When err is nil, this method does nothing.
func (s *Scanner) isCertErrorFatal(err error, logEntry *ct.LogEntry, index int64) bool {
	if err == nil {
		// No error to handle
		return false
	} else if _, ok := err.(x509.NonFatalErrors); ok {
		atomic.AddInt64(&s.entriesWithNonFatalErrors, 1)
		// We'll make a note, but continue.
		s.Log(fmt.Sprintf("Non-fatal error in %v at index %d: %v", logEntry.Leaf.TimestampedEntry.EntryType, index, err))
		return false
	}
	return true
}

// Processes the given entry in the specified log.
func (s *Scanner) processEntry(info entryInfo, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	atomic.AddInt64(&s.certsProcessed, 1)

	switch matcher := s.opts.Matcher.(type) {
	case Matcher:
		return s.processMatcherEntry(matcher, info, foundCert, foundPrecert)
	case LeafMatcher:
		return s.processMatcherLeafEntry(matcher, info, foundCert, foundPrecert)
	default:
		return fmt.Errorf("Unexpected matcher type %T", matcher)
	}
}

func (s *Scanner) processMatcherEntry(matcher Matcher, info entryInfo, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	logEntry, err := ct.LogEntryFromLeaf(info.index, &info.entry)
	if s.isCertErrorFatal(err, logEntry, info.index) {
		return fmt.Errorf("failed to parse [pre-]certificate in MerkleTreeLeaf: %v", err)
	}

	switch {
	case logEntry.X509Cert != nil:
		if s.opts.PrecertOnly {
			// Only interested in precerts and this is an X.509 cert, early-out.
			return nil
		}
		if matcher.CertificateMatches(logEntry.X509Cert) {
			atomic.AddInt64(&s.certsMatched, 1)
			foundCert(logEntry)
		}
	case logEntry.Precert != nil:
		if matcher.PrecertificateMatches(logEntry.Precert) {
			atomic.AddInt64(&s.certsMatched, 1)
			foundPrecert(logEntry)
		}
		atomic.AddInt64(&s.precertsSeen, 1)
	default:
		return fmt.Errorf("saw unknown entry type: %v", logEntry.Leaf.TimestampedEntry.EntryType)
	}
	return nil
}

func (s *Scanner) processMatcherLeafEntry(matcher LeafMatcher, info entryInfo, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	if !matcher.Matches(&info.entry) {
		return nil
	}

	logEntry, err := ct.LogEntryFromLeaf(info.index, &info.entry)
	if logEntry == nil {
		return fmt.Errorf("failed to build log entry: %v", err)
	}
	switch {
	case logEntry.X509Cert != nil:
		if s.opts.PrecertOnly {
			// Only interested in precerts and this is an X.509 cert, early-out.
			return nil
		}
		foundCert(logEntry)
	case logEntry.Precert != nil:
		foundPrecert(logEntry)
		atomic.AddInt64(&s.precertsSeen, 1)
	default:
		return fmt.Errorf("saw unknown entry type: %v", logEntry.Leaf.TimestampedEntry.EntryType)
	}
	return nil
}

// Worker function to match certs.
// Accepts MatcherJobs over the entries channel, and processes them.
// Returns true over the done channel when the entries channel is closed.
func (s *Scanner) matcherJob(entries <-chan entryInfo, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) {
	for e := range entries {
		if err := s.processEntry(e, foundCert, foundPrecert); err != nil {
			atomic.AddInt64(&s.unparsableEntries, 1)
			s.Log(fmt.Sprintf("Failed to parse entry at index %d: %s", e.index, err.Error()))
		}
	}
}

// Pretty prints the passed in duration into a human readable string.
func humanTime(dur time.Duration) string {
	hours := int(dur / time.Hour)
	dur %= time.Hour
	minutes := int(dur / time.Minute)
	dur %= time.Minute
	seconds := int(dur / time.Second)
	s := ""
	if hours > 0 {
		s += fmt.Sprintf("%d hours ", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d minutes ", minutes)
	}
	if seconds > 0 || len(s) == 0 {
		s += fmt.Sprintf("%d seconds ", seconds)
	}
	return s
}

func (s *Scanner) logThroughput(treeSize int64, stop <-chan bool) {
	const wndSize = 15
	wnd := make([]int64, wndSize)
	wndTotal := int64(0)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for slot, filled, prevCnt := 0, 0, int64(0); ; slot = (slot + 1) % wndSize {
		select {
		case <-stop:
			return
		case <-ticker.C:
			certsCnt := atomic.LoadInt64(&s.certsProcessed)
			certsMatched := atomic.LoadInt64(&s.certsMatched)

			slotValue := certsCnt - prevCnt
			wndTotal += slotValue - wnd[slot]
			wnd[slot], prevCnt = slotValue, certsCnt

			if filled < wndSize {
				filled++
			}

			throughput := float64(wndTotal) / float64(filled)
			remainingCerts := treeSize - int64(s.opts.StartIndex) - certsCnt
			remainingSeconds := int(float64(remainingCerts) / throughput)
			remainingString := humanTime(time.Duration(remainingSeconds) * time.Second)
			s.Log(fmt.Sprintf("Processed: %d certs (to index %d), matched %d (%2.2f%%). Throughput (last %ds): %3.2f ETA: %s\n",
				certsCnt, s.opts.StartIndex+certsCnt, certsMatched,
				(100.0*float64(certsMatched))/float64(certsCnt),
				filled, throughput, remainingString))
		}
	}
}

// Scan performs a scan against the Log. Blocks until the scan is complete.
//
// For each x509 certificate found, calls foundCert with the corresponding
// LogEntry, which includes the index of the entry and the certificate.
// For each precert found, calls foundPrecert with the corresponding LogEntry,
// which includes the index of the entry and the precert.
func (s *Scanner) Scan(ctx context.Context, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	s.Log("Starting up Scanner...\n")
	s.certsProcessed = 0
	s.certsMatched = 0
	s.precertsSeen = 0
	s.unparsableEntries = 0
	s.entriesWithNonFatalErrors = 0

	sth, err := s.fetcher.Prepare(ctx)
	if err != nil {
		return err
	}

	startTime := time.Now()
	stop := make(chan bool)
	go s.logThroughput(int64(sth.TreeSize), stop)
	defer func() {
		stop <- true
		close(stop)
	}()

	batches := make(chan EntryBatch) // Output from the Fetcher.
	jobs := make(chan entryInfo, s.opts.BufferSize)
	go func() { // Flatten the output from Fetcher jobs.
		defer close(jobs)
		for b := range batches {
			for i, e := range b.entries {
				jobs <- entryInfo{index: b.start + int64(i), entry: e}
			}
		}
	}()

	// Start matcher workers.
	var wg sync.WaitGroup
	for w, cnt := 0, s.opts.NumWorkers; w < cnt; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s.matcherJob(jobs, foundCert, foundPrecert)
			s.Log(fmt.Sprintf("Matcher %d finished", idx))
		}(w)
	}
	if err := s.fetcher.Run(ctx, batches); err != nil {
		return err // FIXME: What to do with wg?
	}
	close(batches)
	wg.Wait()

	s.Log(fmt.Sprintf("Completed %d certs in %s", atomic.LoadInt64(&s.certsProcessed), humanTime(time.Since(startTime))))
	s.Log(fmt.Sprintf("Saw %d precerts", atomic.LoadInt64(&s.precertsSeen)))
	s.Log(fmt.Sprintf("%d unparsable entries, %d non-fatal errors", atomic.LoadInt64(&s.unparsableEntries), atomic.LoadInt64(&s.entriesWithNonFatalErrors)))

	return nil
}

// NewScanner creates a Scanner instance using client to talk to the log,
// taking configuration options from opts.
func NewScanner(cli *client.LogClient, opts ScannerOptions) *Scanner {
	var scanner Scanner
	scanner.opts = opts
	scanner.fetcher = NewFetcher(cli, &scanner.opts.FetcherOptions)
	scanner.Log = scanner.fetcher.Log

	// Set a default match-everything regex if none was provided:
	if opts.Matcher == nil {
		opts.Matcher = &MatchAll{}
	}
	return &scanner
}
