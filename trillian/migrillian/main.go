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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian"
)

var (
	ctLogURI    = flag.String("ct_log_uri", "http://ct.googleapis.com/aviator", "CT log base URI to fetch entries from")
	trillianURI = flag.String("trillian_uri", "localhost:8091", "Trillian log server URI to add entries to")
	logID       = flag.Int64("log_id", 0, "Trillian log tree ID to add entries to")

	batchSize      = flag.Int("batch_size", 512, "Max number of entries to request per get-entries call")
	parallelFetch  = flag.Int("parallel_fetch", 2, "Number of concurrent get-entries fetchers")
	parallelSubmit = flag.Int("parallel_submit", 2, "Number of concurrent AddSequencedLeaves submitters")

	startIndex = flag.Int64("start_index", 0, "CT log index to start scanning at")
	endIndex   = flag.Int64("end_index", 0, "CT log index to end scanning at (non-inclusive, 0 = end of log)")

	quiet = flag.Bool("quiet", false, "Don't print out extra logging messages")
)

// trillianTreeClient is a means of communicating with a Trillian log tree.
type trillianTreeClient struct {
	client    trillian.TrillianLogClient
	logID     int64
	logPrefix string
}

// addSequencedLeaves converts a batch of CT log entries into Trillian log
// leaves and submits them to Trillian via AddSequencedLeaves API.
func (c *trillianTreeClient) addSequencedLeaves(ctx context.Context, b *scanner.EntryBatch) error {
	// TODO(pavelkalinnikov): Verify range inclusion against the remote STH.
	leaves := make([]*trillian.LogLeaf, len(b.Entries))
	for i, e := range b.Entries {
		var err error
		if leaves[i], err = buildLogLeaf(c.logPrefix, b.Start+int64(i), &e); err != nil {
			return err
		}
	}

	req := trillian.AddSequencedLeavesRequest{LogId: c.logID, Leaves: leaves}
	rsp, err := c.client.AddSequencedLeaves(ctx, &req)
	if err != nil {
		return fmt.Errorf("AddSequencedLeaves(): %v", err)
	} else if rsp == nil {
		return errors.New("missing AddSequencedLeaves response")
	}
	// TODO(pavelkalinnikov): Check rsp.Results statuses.
	return nil
}

// logEntrySubmitter is a worker function which takes CT log entry batches from
// the channel and processes them. Terminates when the channel is closed.
func logEntrySubmitter(ctx context.Context, c trillianTreeClient, batches <-chan scanner.EntryBatch) {
	for b := range batches {
		// TODO(pavelkalinnikov): Retry with backoff on errors.
		err := c.addSequencedLeaves(ctx, &b)
		if *quiet {
			continue
		}
		end := b.Start + int64(len(b.Entries))
		if err != nil {
			glog.Infof("Failed to add batch [%d, %d): %v\n", b.Start, end, err)
		} else {
			glog.Errorf("Added batch [%d, %d)\n", b.Start, end)
		}
	}
}

func main() {
	flag.Parse()

	transport := &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	ctClient, err := client.New(*ctLogURI, &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}, jsonclient.Options{})
	if err != nil {
		glog.Exitf("Failed to create client for source log: %v", err)
	}

	opts := &scanner.FetcherOptions{
		BatchSize:     *batchSize,
		ParallelFetch: *parallelFetch,
		StartIndex:    *startIndex,
		EndIndex:      *endIndex,
		Quiet:         *quiet,
	}
	fetcher := scanner.NewFetcher(ctClient, opts)

	bufferSize := 10 * *parallelSubmit
	batches := make(chan scanner.EntryBatch, bufferSize)

	glog.Infof("Dialing Trillian...")
	conn, err := grpc.Dial(*trillianURI,
		grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second), grpc.FailOnNonTempDialError(true),
	)
	if err != nil {
		glog.Exitf("Could not dial Trillian server %q: %v", *trillianURI, err)
	}
	defer conn.Close()
	glog.Infof("Connected to Trillian")

	treeClient := trillianTreeClient{
		client:    trillian.NewTrillianLogClient(conn),
		logID:     *logID,
		logPrefix: fmt.Sprintf("%d", *logID),
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	for w := 0; w < *parallelSubmit; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logEntrySubmitter(ctx, treeClient, batches)
		}()
	}

	handler := func(b scanner.EntryBatch) {
		batches <- b
	}
	err = fetcher.Run(ctx, handler)
	close(batches)
	wg.Wait()

	if err != nil {
		glog.Exitf("Fetcher.Run() returned error: %v", err)
	}
}
