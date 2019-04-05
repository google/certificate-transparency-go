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

package submission

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Flags.
var (
	httpEndpoint           = flag.String("http_endpoint", "localhost:5951", "Endpoint for HTTP (host:port)")
	logListPath            = flag.String("loglist_path", "https://www.gstatic.com/ct/log_list/log_list.json", "Path for list of CT Logs in JSON format")
	logListRefreshInterval = flag.Duration("loglist_refresh_interval", 2*24*time.Hour, "Interval between consecutive reads of Log-list.")
	rootsRefreshInterval   = flag.Duration("roots_refresh_interval", 24*time.Hour, "Interval between consecutive get-roots calls.")
	policyType             = flag.String("policy_type", "chrome", "CT-policy <chrome|apple>.")
	logClientType          = flag.String("log_client_type", "stub", "Log-client <stub|prod>.")
	addPreChainTimeout     = flag.Duration("add_prechain_timeout", 10*time.Second, "Timeout for each add-prechain call")
)

func parsePolicyType() CTPolicyType {
	if *policyType == "chrome" {
		return ChromeCTPolicy
	} else if *policyType == "apple" {
		return AppleCTPolicy
	}
	panic(fmt.Sprintf("flag policyType does not support value %q", *policyType))
}

func parseLogClientType() LogClientBuilder {
	if *logClientType == "prod" {
		return BuildLogClient
	} else if *logClientType == "stub" {
		return newStubLogClient
	}
	panic(fmt.Sprintf("flag logClientType does not support value %q", *logClientType))
}

func main() {
	flag.Parse()

	s := newServer()
	s.routes()
	log.Fatal(http.ListenAndServe(*httpEndpoint, nil))
}

// Server wraps Proxy and handles http-requests for it.
type server struct {
	p *Proxy
}

// newServer creates and inits Server instance.
func newServer() *server {
	plc := parsePolicyType()
	lcBuilder := parseLogClientType()

	s := &server{}
	s.p = NewProxy(NewLogListRefresher(*logListPath), GetDistributorBuilder(plc, lcBuilder))
	s.p.Run(context.Background(), *logListRefreshInterval, *rootsRefreshInterval)
	return s
}
