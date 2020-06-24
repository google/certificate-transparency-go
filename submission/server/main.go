// Copyright 2019 Google LLC. All Rights Reserved.
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

// The submission_server runs (pre-)certs multi-Log submission complying with
// CT-policy provided.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/submission"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Flags.
var (
	httpEndpoint             = flag.String("http_endpoint", "localhost:5951", "Endpoint for HTTP (host:port)")
	logListPath              = flag.String("loglist_path", "https://www.gstatic.com/ct/log_list/v2/log_list.json", "Path for list of CT Logs in JSON format")
	logListRefreshInterval   = flag.Duration("loglist_refresh_interval", 24*time.Hour, "Interval between consecutive reads of Log-list")
	rootsRefreshInterval     = flag.Duration("roots_refresh_interval", 24*time.Hour, "Interval between consecutive get-roots calls")
	policyType               = flag.String("policy_type", "chrome", "CT-policy <chrome|apple>")
	dryRun                   = flag.Bool("dry_run", false, "No real submissions done")
	addPreChainTimeout       = flag.Duration("add_prechain_timeout", 10*time.Second, "Timeout for each add-prechain call")
	loadPendingQualifiedLogs = flag.Bool("load_pending_qualified_logs", true, "Whether to submit cert to one of Pending+Qualified Logs along main submission")
)

func parsePolicyType() submission.CTPolicyType {
	if *policyType == "chrome" {
		return submission.ChromeCTPolicy
	} else if *policyType == "apple" {
		return submission.AppleCTPolicy
	}
	glog.Fatalf("flag policyType does not support value %q", *policyType)
	return submission.ChromeCTPolicy
}

func main() {
	flag.Parse()

	plc := parsePolicyType()

	lcb := submission.BuildLogClient
	if *dryRun {
		lcb = submission.NewStubLogClient
	}
	mf := prometheus.MetricFactory{}

	s := submission.NewProxyServer(*logListPath, submission.GetDistributorBuilder(plc, lcb, mf), *addPreChainTimeout, mf)
	s.Run(context.Background(), *logListRefreshInterval, *rootsRefreshInterval, *loadPendingQualifiedLogs)
	http.HandleFunc("/ct/v1/proxy/add-pre-chain/", s.HandleAddPreChain)
	http.HandleFunc("/ct/v1/proxy/add-chain/", s.HandleAddChain)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", s.HandleInfo)
	log.Fatal(http.ListenAndServe(*httpEndpoint, nil))
}
