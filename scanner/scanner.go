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
	"container/list"
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
)

// ScannerOptions holds configuration options for the Scanner
type ScannerOptions struct { // nolint:golint
	// Custom matcher for x509 Certificates, functor will be called for each
	// Certificate found during scanning.  Should be a Matcher or LeafMatcher
	// implementation.
	Matcher interface{}

	// Match precerts only (Matcher still applies to precerts)
	PrecertOnly bool

	// Number of entries to request in one batch from the Log
	BatchSize int

	// Number of concurrent matchers to run
	NumWorkers int

	// Number of concurrent fethers to run
	ParallelFetch int

	// Number of fetched entries to buffer on their way to the callbacks
	BufferSize int

	// Log entry index to start fetching & matching at
	StartIndex int64

	// Don't print any status messages to stdout
	Quiet bool
}

// DefaultScannerOptions creates a new ScannerOptions struct with sensible defaults.
func DefaultScannerOptions() *ScannerOptions {
	return &ScannerOptions{
		Matcher:       &MatchAll{},
		PrecertOnly:   false,
		BatchSize:     1000,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    0,
		Quiet:         false,
	}
}

// Scanner is a tool to scan all the entries in a CT Log.
type Scanner struct {
	// Client used to talk to the CT log instance
	logClient *client.LogClient

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

// entryInfo represents information about a log entry
type entryInfo struct {
	// The index of the entry containing the LeafInput in the log
	index int64
	// The log entry returned by the log server
	entry ct.LeafEntry
}

// fetchRange represents a range of certs to fetch from a CT log
type fetchRange struct {
	start int64 // inclusive
	end   int64 // inclusive
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

// Worker function for fetcher jobs.
// Accepts cert ranges to fetch over the ranges channel, and if the fetch is
// successful sends the individual LeafInputs out (as MatcherJobs) into the
// entries channel for the matchers to chew on.
// Will retry failed attempts to retrieve ranges indefinitely.
// Sends true over the done channel when the ranges channel is closed.
func (s *Scanner) fetcherJob(ctx context.Context, ranges <-chan fetchRange, entries chan<- entryInfo) {
	for r := range ranges {
		success := false
		// TODO(alcutter): give up after a while:
		for !success {
			resp, err := s.logClient.GetRawEntries(ctx, r.start, r.end)
			if err != nil {
				s.Log(fmt.Sprintf("Problem fetching from log: %s", err.Error()))
				continue
			}
			for _, leafEntry := range resp.Entries {
				entries <- entryInfo{r.start, leafEntry}
				r.start++
			}
			if r.start > r.end {
				// Only complete if we actually got all the leaves we were
				// expecting -- Logs MAY return fewer than the number of
				// leaves requested.
				success = true
			}
		}
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
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
	if seconds > 0 {
		s += fmt.Sprintf("%d seconds ", seconds)
	}
	return s
}

func (s *Scanner) logThroughput(treeSize int64, stop <-chan bool) {
	const wndSize = 15
	wnd := make([]int64, wndSize)
	wndTotal := int64(0)

	ticker := time.NewTicker(time.Second)
	for slot, slots, prevCnt := 0, 0, int64(0); ; slot = (slot + 1) % wndSize {
		select {
		case <-stop:
			break
		case <-ticker.C:
			certsCnt := atomic.LoadInt64(&s.certsProcessed)
			certsMatched := atomic.LoadInt64(&s.certsMatched)

			slotValue := certsCnt - prevCnt
			wndTotal += slotValue - wnd[slot]
			wnd[slot], prevCnt = slotValue, certsCnt

			if slots < wndSize {
				slots++
			}

			throughput := float64(wndTotal) / float64(slots)
			remainingCerts := treeSize - int64(s.opts.StartIndex) - certsCnt
			remainingSeconds := int(float64(remainingCerts) / throughput)
			remainingString := humanTime(time.Duration(remainingSeconds) * time.Second)
			s.Log(fmt.Sprintf("Processed: %d certs (to index %d), matched %d (%2.2f%%). Throughput (last %ds): %3.2f ETA: %s\n",
				certsCnt, s.opts.StartIndex+certsCnt, certsMatched,
				(100.0*float64(certsMatched))/float64(certsCnt),
				slots, throughput, remainingString))
		}
	}

	ticker.Stop()
}

// Scan performs a scan against the Log.
//
// For each x509 certificate found, foundCert will be called with the
// corresponding LogEntry (which includes the index of the entry and the
// certificate itself). For each precert found, foundPrecert will be called
// with the precert incorporated in the LogEntry.
//
// This method blocks until the scan is complete.
func (s *Scanner) Scan(ctx context.Context, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	s.Log("Starting up...\n")
	s.certsProcessed = 0
	s.certsMatched = 0
	s.precertsSeen = 0
	s.unparsableEntries = 0
	s.entriesWithNonFatalErrors = 0

	sth, err := s.logClient.GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to GetSTH(): %v", err)
	}
	s.Log(fmt.Sprintf("Got STH with %d certs", sth.TreeSize))

	startTime := time.Now()
	stop := make(chan bool)
	go s.logThroughput(int64(sth.TreeSize), stop)
	defer func() {
		stop <- true
		close(stop)
	}()

	fetches := make(chan fetchRange)
	jobs := make(chan entryInfo, s.opts.BufferSize)

	var ranges list.List
	// TODO(pavelkalinnikov): Add EndIndex parameter.
	for start := s.opts.StartIndex; start < int64(sth.TreeSize); {
		end := min(start+int64(s.opts.BatchSize), int64(sth.TreeSize)) - 1
		ranges.PushBack(fetchRange{start, end})
		start = end + 1
	}
	var fetcherWG sync.WaitGroup
	var matcherWG sync.WaitGroup
	// Start matcher workers
	for w := 0; w < s.opts.NumWorkers; w++ {
		matcherWG.Add(1)
		go func(w int) {
			defer matcherWG.Done()
			s.matcherJob(jobs, foundCert, foundPrecert)
			s.Log(fmt.Sprintf("Matcher %d finished", w))
		}(w)
	}
	// Start fetcher workers
	for w := 0; w < s.opts.ParallelFetch; w++ {
		fetcherWG.Add(1)
		go func(w int) {
			defer fetcherWG.Done()
			s.fetcherJob(ctx, fetches, jobs)
			s.Log(fmt.Sprintf("Fetcher %d finished", w))
		}(w)
	}
	for r := ranges.Front(); r != nil; r = r.Next() {
		fetches <- r.Value.(fetchRange)
	}
	close(fetches)
	fetcherWG.Wait()
	close(jobs)
	matcherWG.Wait()

	s.Log(fmt.Sprintf("Completed %d certs in %s", atomic.LoadInt64(&s.certsProcessed), humanTime(time.Since(startTime))))
	s.Log(fmt.Sprintf("Saw %d precerts", atomic.LoadInt64(&s.precertsSeen)))
	s.Log(fmt.Sprintf("%d unparsable entries, %d non-fatal errors", atomic.LoadInt64(&s.unparsableEntries), atomic.LoadInt64(&s.entriesWithNonFatalErrors)))

	return nil
}

// New creates a Scanner instance using client to talk to the log, taking
// configuration options from opts.
func New(client *client.LogClient, opts ScannerOptions) *Scanner {
	var scanner Scanner
	scanner.logClient = client
	// Set a default match-everything regex if none was provided:
	if opts.Matcher == nil {
		opts.Matcher = &MatchAll{}
	}
	if opts.Quiet {
		scanner.Log = func(msg string) {}
	} else {
		scanner.Log = func(msg string) { log.Print(msg) }
	}
	scanner.opts = opts
	return &scanner
}
