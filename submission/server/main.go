// Copyright 2019 Google Inc. All Rights Reserved.
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
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-go/submission"
)

// Flags.
var (
	httpEndpoint           = flag.String("http_endpoint", "localhost:5951", "Endpoint for HTTP (host:port)")
	logListPath            = flag.String("loglist_path", "https://www.gstatic.com/ct/log_list/log_list.json", "Path for list of CT Logs in JSON format")
	logListRefreshInterval = flag.Duration("loglist_refresh_interval", 2*24*time.Hour, "Interval between consecutive reads of Log-list")
	rootsRefreshInterval   = flag.Duration("roots_refresh_interval", 24*time.Hour, "Interval between consecutive get-roots calls")
	policyType             = flag.String("policy_type", "chrome", "CT-policy <chrome|apple>")
	dryRun                 = flag.Bool("dry_run", false, "Whether stub Log client should be used instead of prod one")
	addPreChainTimeout     = flag.Duration("add_prechain_timeout", 10*time.Second, "Timeout for each add-prechain call")
)

func parsePolicyType() submission.CTPolicyType {
	if *policyType == "chrome" {
		return submission.ChromeCTPolicy
	} else if *policyType == "apple" {
		return submission.AppleCTPolicy
	}
	panic(fmt.Sprintf("flag policyType does not support value %q", *policyType))
}

func main() {
	flag.Parse()

	plc := parsePolicyType()
	var lcType submission.LogClientBuilder
	if *dryRun {
		lcType = submission.NewStubLogClient
	} else {
		lcType = submission.BuildLogClient
	}

	s := submission.NewProxyServer(
		*logListPath, *logListRefreshInterval, *rootsRefreshInterval,
		submission.GetDistributorBuilder(plc, lcType), *addPreChainTimeout)
	http.Handle("ct/v1/proxy/add-pre-chain/", s.HandleAddPreChain())
	log.Fatal(http.ListenAndServe(*httpEndpoint, nil))
}
