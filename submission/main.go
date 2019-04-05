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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
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
		return buildStubLC
	}
	panic(fmt.Sprintf("flag logClientType does not support value %q", *logClientType))
}

func main() {
	flag.Parse()

	s := NewServer()
	s.routes()
	log.Fatal(http.ListenAndServe(*httpEndpoint, nil))
}

// Server wraps Proxy and handles http-requests for it.
type Server struct {
	p *Proxy
}

// NewServer creates and inits Server instance.
func NewServer() *Server {
	plc := parsePolicyType()
	lcBuilder := parseLogClientType()

	s := &Server{}
	s.p = NewProxy(NewLogListRefresher(*logListPath), GetDistributorBuilder(plc, lcBuilder))
	s.p.Run(context.Background(), *logListRefreshInterval, *rootsRefreshInterval)
	return s
}

func (s *Server) routes() {
	http.Handle("ct/v1/proxy/add-pre-chain/", s.handleAddPreChain())
}

func marshalSCTs(scts []*AssignedSCT) []byte {
	var jsonSCTsObj struct {
		SCTs []ct.SignedCertificateTimestamp `json:"scts"`
	}
	jsonSCTsObj.SCTs = make([]ct.SignedCertificateTimestamp, len(scts))
	for _, sct := range scts {
		jsonSCTsObj.SCTs = append(jsonSCTsObj.SCTs, *sct.SCT)
	}
	jsonSCTs, _ := json.Marshal(jsonSCTsObj)
	return jsonSCTs
}

func (s *Server) handleAddPreChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		addChainReq, err := ctfe.ParseBodyAsJSONChain(r)
		if err != nil {
			rc := http.StatusBadRequest
			http.Error(w, fmt.Sprintf("proxy: failed to parse add-pre-chain body: %s", err), rc)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), *addPreChainTimeout)
		defer cancel()

		scts, err := s.p.AddPreChain(ctx, addChainReq.Chain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		data := marshalSCTs(scts)
		fmt.Fprint(w, string(data))
	}
}
