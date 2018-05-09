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

// Migrillian tool transfers certs from CT logs to Trillian pre-ordered logs in
// the same order.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/trillian/migrillian/core"
	"github.com/google/trillian"
)

var (
	ctLogURI    = flag.String("ct_log_uri", "http://ct.googleapis.com/aviator", "CT log base URI to fetch entries from")
	trillianURI = flag.String("trillian_uri", "localhost:8090", "Trillian log server URI to add entries to")
	logID       = flag.Int64("log_id", 0, "Trillian log tree ID to add entries to")

	maxIdleConnsPerHost = flag.Int("max_idle_conns_per_host", 10, "Max idle HTTP connections per host (0 = DefaultMaxIdleConnsPerHost)")
	maxIdleConns        = flag.Int("max_idle_conns", 100, "Max number of idle HTTP connections across all hosts (0 = unlimited)")
	dialTimeout         = flag.Duration("grpc_dial_timeout", 5*time.Second, "Timeout for dialling Trillian")

	ctBatchSize      = flag.Int("ct_batch_size", 512, "Max number of entries to request per get-entries call")
	ctFetchers       = flag.Int("ct_fetchers", 2, "Number of concurrent get-entries fetchers")
	submitters       = flag.Int("submitters", 2, "Number of concurrent workers submitting entries to Trillian")
	submitterBatches = flag.Int("submitter_batches", 5, "Max number of batches per submitter in fetchers->submitters channel")

	startIndex = flag.Int64("start_index", 0, "CT log index to start scanning at")
	endIndex   = flag.Int64("end_index", 0, "CT log index to end scanning at (non-inclusive, 0 = end of log)")

	verbose = flag.Bool("verbose", false, "Print out extra logging messages")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	opts := core.Options{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     *ctBatchSize,
			ParallelFetch: *ctFetchers,
			StartIndex:    *startIndex,
			EndIndex:      *endIndex,
			Quiet:         !*verbose,
		},

		Submitters:          *submitters,
		BatchesPerSubmitter: *submitterBatches,
	}
	ctrl := core.NewController(opts)

	transport := &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConns:          *maxIdleConns,
		MaxIdleConnsPerHost:   *maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	ctClient, err := client.New(*ctLogURI, &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}, jsonclient.Options{})
	if err != nil {
		glog.Exitf("Failed to create CT client for log at %q: %v", *ctLogURI, err)
	}
	glog.Info("Created CT client")

	cctx, cancel := context.WithTimeout(ctx, *dialTimeout)
	conn, err := grpc.DialContext(cctx, *trillianURI,
		grpc.WithInsecure(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
	cancel()
	if err != nil {
		glog.Exitf("Could not dial Trillian server %q: %v", *trillianURI, err)
	}
	defer conn.Close()
	glog.Info("Connected to Trillian")

	treeClient := &core.TrillianTreeClient{
		Client:    trillian.NewTrillianLogClient(conn),
		LogID:     *logID,
		LogPrefix: fmt.Sprintf("%d", *logID),
	}

	cctx, cancel = core.WithSignalCancel(ctx)
	defer cancel()
	if err = ctrl.Run(cctx, ctClient, treeClient); err != nil {
		glog.Exitf("Controller.Run() returned error: %v", err)
	}
}
