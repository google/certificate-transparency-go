// Copyright 2017 Google LLC. All Rights Reserved.
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

// ct_hammer is a stress/load test for a CT log.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/fixchain/ratelimiter"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/integration"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	banner      = flag.Bool("banner", true, "Display intro")
	httpServers = flag.String("ct_http_servers", "localhost:8092", "Comma-separated list of (assumed interchangeable) servers, each as address:port")

	// Options for synthetic cert generation.
	testDir      = flag.String("testdata_dir", "testdata", "Name of directory with test data")
	leafNotAfter = flag.String("leaf_not_after", "", "Not-After date to use for leaf certs, RFC3339/ISO-8601 format (e.g. 2017-11-26T12:29:19Z)")
	// Options for copied-cert generation.
	srcLogURI       = flag.String("src_log_uri", "", "URI for source log to copy certificates from")
	srcPubKey       = flag.String("src_pub_key", "", "Name of file containing source log's public key")
	srcLogName      = flag.String("src_log_name", "", "Name of source log to copy certificate from  (from --log_list)")
	logList         = flag.String("log_list", loglist.AllLogListURL, "Location of master log list (URL or filename)")
	skipHTTPSVerify = flag.Bool("skip_https_verify", false, "Skip verification of HTTPS transport connection to source log")
	chainBufSize    = flag.Int("buffered_chains", 100, "Number of buffered certificate chains to hold")
	startIndex      = flag.Int64("start_index", 0, "Index of start point in source log to scan from (-1 for random start index)")
	batchSize       = flag.Int("batch_size", 500, "Max number of entries to request at per call to get-entries")
	parallelFetch   = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")

	metricsEndpoint     = flag.String("metrics_endpoint", "", "Endpoint for serving metrics; if left empty, metrics will not be exposed")
	seed                = flag.Int64("seed", -1, "Seed for random number generation")
	logConfig           = flag.String("log_config", "", "File holding log config in JSON")
	mmd                 = flag.Duration("mmd", 2*time.Minute, "Default MMD for logs")
	operations          = flag.Uint64("operations", ^uint64(0), "Number of operations to perform")
	minGetEntries       = flag.Int("min_get_entries", 1, "Minimum get-entries request size")
	maxGetEntries       = flag.Int("max_get_entries", 500, "Maximum get-entries request size")
	oversizedGetEntries = flag.Bool("oversized_get_entries", false, "Whether get-entries requests can go beyond log size")
	maxParallelChains   = flag.Int("max_parallel_chains", 2, "Maximum number of chains to add in parallel (will always add at least 1 chain)")
	limit               = flag.Int("rate_limit", 0, "Maximum rate of requests to an individual log; 0 for no rate limit")
	ignoreErrors        = flag.Bool("ignore_errors", false, "Whether to ignore errors and retry the operation")
	maxRetry            = flag.Duration("max_retry", 60*time.Second, "How long to keep retrying when ignore_errors is set")
	reqDeadline         = flag.Duration("req_deadline", 10*time.Second, "Deadline to set on individual requests")
)
var (
	addChainBias             = flag.Int("add_chain", 20, "Bias for add-chain operations")
	addPreChainBias          = flag.Int("add_pre_chain", 20, "Bias for add-pre-chain operations")
	getSTHBias               = flag.Int("get_sth", 2, "Bias for get-sth operations")
	getSTHConsistencyBias    = flag.Int("get_sth_consistency", 2, "Bias for get-sth-consistency operations")
	getProofByHashBias       = flag.Int("get_proof_by_hash", 2, "Bias for get-proof-by-hash operations")
	getEntriesBias           = flag.Int("get_entries", 2, "Bias for get-entries operations")
	getRootsBias             = flag.Int("get_roots", 1, "Bias for get-roots operations")
	getEntryAndProofBias     = flag.Int("get_entry_and_proof", 0, "Bias for get-entry-and-proof operations")
	invalidChance            = flag.Int("invalid_chance", 10, "Chance of generating an invalid operation, as the N in 1-in-N (0 for never)")
	dupeChance               = flag.Int("duplicate_chance", 10, "Chance of generating a duplicate submission, as the N in 1-in-N (0 for never)")
	strictSTHConsistencySize = flag.Bool("strict_sth_consistency_size", true, "If set to true, hammer will use only tree sizes from STHs it's seen for consistency proofs, otherwise it'll choose a random size for the smaller tree")
)

func newLimiter(rate int) integration.Limiter {
	if rate <= 0 {
		return nil
	}
	return ratelimiter.NewLimiter(rate)
}

// copierGeneratorFactory returns a function that creates per-Log ChainGenerator instances
// that are based off a source CT log specified by the command line arguments.
func copierGeneratorFactory(ctx context.Context) integration.GeneratorFactory {
	var tlsCfg *tls.Config
	if *skipHTTPSVerify {
		glog.Warning("Skipping HTTPS connection verification")
		tlsCfg = &tls.Config{InsecureSkipVerify: *skipHTTPSVerify}
	}
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsCfg,
		},
	}
	uri := *srcLogURI
	var opts jsonclient.Options
	if *srcPubKey != "" {
		pubkey, err := ioutil.ReadFile(*srcPubKey)
		if err != nil {
			glog.Exit(err)
		}
		opts.PublicKey = string(pubkey)
	}
	if len(*srcLogName) > 0 {
		llData, err := x509util.ReadFileOrURL(*logList, httpClient)
		if err != nil {
			glog.Exitf("Failed to read log list: %v", err)
		}
		ll, err := loglist.NewFromJSON(llData)
		if err != nil {
			glog.Exitf("Failed to build log list: %v", err)
		}

		logs := ll.FindLogByName(*srcLogName)
		if len(logs) == 0 {
			glog.Exitf("No log with name like %q found in loglist %q", *srcLogName, *logList)
		}
		if len(logs) > 1 {
			logNames := make([]string, len(logs))
			for i, log := range logs {
				logNames[i] = fmt.Sprintf("%q", log.Description)
			}
			glog.Exitf("Multiple logs with name like %q found in loglist: %s", *srcLogName, strings.Join(logNames, ","))
		}
		uri = "https://" + logs[0].URL
		if opts.PublicKey == "" {
			opts.PublicKeyDER = logs[0].Key
		}
	}

	logClient, err := client.New(uri, httpClient, opts)
	if err != nil {
		glog.Exitf("Failed to create client for %q: %v", uri, err)
	}
	glog.Infof("Testing with certs copied from log at %s starting at index %d", uri, *startIndex)
	genOpts := integration.CopyChainOptions{
		StartIndex:    *startIndex,
		BufSize:       *chainBufSize,
		BatchSize:     *batchSize,
		ParallelFetch: *parallelFetch,
	}
	return func(c *configpb.LogConfig) (integration.ChainGenerator, error) {
		return integration.NewCopyChainGeneratorFromOpts(ctx, logClient, c, genOpts)
	}
}

func main() {
	flag.Parse()
	if *logConfig == "" {
		glog.Exit("Test aborted as no log config provided (via --log_config)")
	}
	if *seed == -1 {
		*seed = time.Now().UTC().UnixNano() & 0xFFFFFFFF
	}
	fmt.Printf("Today's test has been brought to you by the letters C and T and the number %#x\n", *seed)
	rand.Seed(*seed)

	cfg, err := ctfe.LogConfigFromFile(*logConfig)
	if err != nil {
		glog.Exitf("Failed to read log config: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var generatorFactory integration.GeneratorFactory
	if len(*srcLogURI) > 0 || len(*srcLogName) > 0 {
		// Test cert chains will be generated by copying from a source log.
		generatorFactory = copierGeneratorFactory(ctx)
	} else if *testDir != "" {
		// Test cert chains will be generated as synthetic certs from a template.
		// Retrieve the test data holding the template and key.
		glog.Infof("Testing with synthetic certs based on data from %s", *testDir)
		generatorFactory, err = integration.SyntheticGeneratorFactory(*testDir, *leafNotAfter)
		if err != nil {
			glog.Exitf("Failed to make cert generator: %v", err)
		}
	}

	if generatorFactory == nil {
		glog.Warningf("Warning: add-[pre-]chain operations disabled as no cert generation method available")
		*addChainBias = 0
		*addPreChainBias = 0
		generatorFactory = func(c *configpb.LogConfig) (integration.ChainGenerator, error) {
			return nil, nil
		}
	}

	bias := integration.HammerBias{
		Bias: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          *addChainBias,
			ctfe.AddPreChainName:       *addPreChainBias,
			ctfe.GetSTHName:            *getSTHBias,
			ctfe.GetSTHConsistencyName: *getSTHConsistencyBias,
			ctfe.GetProofByHashName:    *getProofByHashBias,
			ctfe.GetEntriesName:        *getEntriesBias,
			ctfe.GetRootsName:          *getRootsBias,
			ctfe.GetEntryAndProofName:  *getEntryAndProofBias,
		},
		InvalidChance: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          *invalidChance,
			ctfe.AddPreChainName:       *invalidChance,
			ctfe.GetSTHName:            0,
			ctfe.GetSTHConsistencyName: *invalidChance,
			ctfe.GetProofByHashName:    *invalidChance,
			ctfe.GetEntriesName:        *invalidChance,
			ctfe.GetRootsName:          0,
			ctfe.GetEntryAndProofName:  0,
		},
	}

	var mf monitoring.MetricFactory
	if *metricsEndpoint != "" {
		mf = prometheus.MetricFactory{}
		http.Handle("/metrics", promhttp.Handler())
		server := http.Server{Addr: *metricsEndpoint, Handler: nil}
		glog.Infof("Serving metrics at %v", *metricsEndpoint)
		go func() {
			err := server.ListenAndServe()
			glog.Warningf("Metrics server exited: %v", err)
		}()
	} else {
		mf = monitoring.InertMetricFactory{}
	}

	if *banner {
		fmt.Print("\n\nStop")
		for i := 0; i < 8; i++ {
			time.Sleep(100 * time.Millisecond)
			fmt.Print(".")
		}
		mc := "H4sIAAAAAAAA/4xVPbLzMAjsv1OkU8FI9LqDOAUFDUNBxe2/QXYSS/HLe5SeXZYfsf73+D1KB8D2B2RxZpGw8gcsSoQYeH1ya0fof1BpnhpuUR+P8ijorESq8Yto6WYWqsrMGh4qSkdI/YFZWu8d3AAAkklEHBGTNAYxbpKltWRgRzQ3A3CImDIjVSVCicThbLK0VjsiAGAGIIKbmUcIq/KkqYo4BNZDqtgZMAPNPSJCRISZZ36d5OiTUbqJZAOYIoCHUreImJsCPMobQ20SqjBbLWWbBGRREhHQU2MMUu9TwB12cC7X3SNrs1yPKvv5gD4yn+kzshOfMg69fVknJNbdcsjuDvgNXWPmTXCuEnuvP4NdlSWymIQjfsFWzbERZ5sz730NpbvoOGMOzu7eeBUaW3w8r4z2iRuD4uY6W9wgZ96+YZvpHW7SabvlH7CviKWQyp81EL2zj7Fcbee7MpSuNHzj2z18LdAvAkAr8pr/3cGFUO+apa2n64TK3XouTBpEch2Rf8GnzajAFY438+SzgURfV7sXT+q1FNTJYdLF9WxJzFheAyNmXfKuiel5/mW2QqSx2umlQ+L2GpTPWZBu5tvpXW5/fy4xTYd2ly+vR052dZbjTIh0u4vzyRDF6kPzoRLRfhp2pqnr5wce5eAGP6onaRv8EYdl7gfd5zIId/gxYvr4pWW7KnbjoU6kRL62e25b44ZQz7Oaf4GrTovnqemNsyOdL40Dls11ocMPn29nYeUvmt3S1v8DAAD//wEAAP//TRo+KHEIAAA="
		mcData, _ := base64.StdEncoding.DecodeString(mc)
		b := bytes.NewReader(mcData)
		r, _ := gzip.NewReader(b)
		io.Copy(os.Stdout, r)
		r.Close()
		fmt.Print("\n\nHammer Time\n\n")
	}

	type result struct {
		prefix string
		err    error
	}
	results := make(chan result, len(cfg))
	var wg sync.WaitGroup
	for _, c := range cfg {
		wg.Add(1)
		pool, err := integration.NewRandomPool(*httpServers, c.PublicKey, c.Prefix)
		if err != nil {
			glog.Exitf("Failed to create client pool: %v", err)
		}

		mmd := *mmd
		// Note: Although the (usually lower than MMD) expected merge delay is not
		// a guarantee, it should be OK for testing.
		if emd := c.ExpectedMergeDelaySec; emd != 0 {
			mmd = time.Second * time.Duration(emd)
		}

		generator, err := generatorFactory(c)
		if err != nil {
			glog.Exitf("Failed to build chain generator: %v", err)
		}

		cfg := integration.HammerConfig{
			LogCfg:                   c,
			MetricFactory:            mf,
			MMD:                      mmd,
			ChainGenerator:           generator,
			ClientPool:               pool,
			EPBias:                   bias,
			MinGetEntries:            *minGetEntries,
			MaxGetEntries:            *maxGetEntries,
			OversizedGetEntries:      *oversizedGetEntries,
			Operations:               *operations,
			Limiter:                  newLimiter(*limit),
			MaxParallelChains:        *maxParallelChains,
			IgnoreErrors:             *ignoreErrors,
			MaxRetryDuration:         *maxRetry,
			RequestDeadline:          *reqDeadline,
			DuplicateChance:          *dupeChance,
			StrictSTHConsistencySize: *strictSTHConsistencySize,
		}
		go func(cfg integration.HammerConfig) {
			defer wg.Done()
			err := integration.HammerCTLog(cfg)
			results <- result{prefix: cfg.LogCfg.Prefix, err: err}
		}(cfg)
	}
	wg.Wait()

	glog.Infof("completed tests on all %d logs:", len(cfg))
	close(results)
	errCount := 0
	for e := range results {
		if e.err != nil {
			errCount++
			glog.Errorf("  %s: failed with %v", e.prefix, e.err)
		}
	}
	if errCount > 0 {
		glog.Exitf("non-zero error count (%d), exiting", errCount)
	}
	glog.Info("  no errors; done")
}
