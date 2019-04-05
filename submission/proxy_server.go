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
	"fmt"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
)

// ProxyServer wraps Proxy and handles http-requests for it.
type ProxyServer struct {
	p          *Proxy
	addTimeout time.Duration
}

// NewProxyServer creates and inits ProxyServer instance.
func NewProxyServer(logListPath string, logListRefreshInterval time.Duration, rootsRefreshInterval time.Duration, dBuilder DistributorBuilder, reqTimeout time.Duration) *ProxyServer {
	s := &ProxyServer{addTimeout: reqTimeout}
	s.p = NewProxy(NewLogListRefresher(logListPath), dBuilder)
	s.p.Run(context.Background(), logListRefreshInterval, rootsRefreshInterval)
	return s
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

// HandleAddPreChain http handler for multiplexed add-pre-chain request.
func (s *ProxyServer) HandleAddPreChain() http.HandlerFunc {
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

		ctx, cancel := context.WithTimeout(context.Background(), s.addTimeout)
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
