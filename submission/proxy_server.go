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
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
)

// ProxyServer wraps Proxy and handles HTTP-requests for it.
type ProxyServer struct {
	p          *Proxy
	addTimeout time.Duration
}

// NewProxyServer creates ProxyServer instance. Call Run() to init.
func NewProxyServer(logListPath string, dBuilder DistributorBuilder, reqTimeout time.Duration) *ProxyServer {
	s := &ProxyServer{addTimeout: reqTimeout}
	s.p = NewProxy(NewLogListRefresher(logListPath), dBuilder)
	return s
}

// Run starts regular Log list updates.
func (s *ProxyServer) Run(logListRefreshInterval time.Duration, rootsRefreshInterval time.Duration) {
	s.p.Run(context.Background(), logListRefreshInterval, rootsRefreshInterval)
}

// SCTBatch represents JSON response to add-pre-chain method of proxy.
type SCTBatch struct {
	SCTs []ct.SignedCertificateTimestamp `json:"scts"`
}

func marshalSCTs(scts []*AssignedSCT) ([]byte, error) {
	var jsonSCTsObj SCTBatch
	jsonSCTsObj.SCTs = make([]ct.SignedCertificateTimestamp, 0, len(scts))
	for _, sct := range scts {
		jsonSCTsObj.SCTs = append(jsonSCTsObj.SCTs, *sct.SCT)
	}
	return json.Marshal(jsonSCTsObj)
}

// HandleAddPreChain handles multiplexed add-pre-chain HTTP request.
func (s *ProxyServer) HandleAddPreChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		addChainReq, err := ctfe.ParseBodyAsJSONChain(r)
		if err != nil {
			rc := http.StatusBadRequest
			http.Error(w, fmt.Sprintf("proxy: failed to parse add-pre-chain body: %s", err), rc)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), s.addTimeout)
		defer cancel()

		scts, err := s.p.AddPreChain(ctx, addChainReq.Chain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		data, err := marshalSCTs(scts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(data))
	}
}

func stringToHTML(s string) template.HTML {
	return template.HTML(strings.Replace(template.HTMLEscapeString(string(s)), "\n", "<br>", -1))
}

type InfoData struct {
	PolicyName string
	LogListPath template.HTML
	LogListJSON template.HTML
}

// HandleInfo handles info-page request.
func (s *ProxyServer) HandleInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := InfoData {
			s.p.dist.policy.Name(),
			stringToHTML(s.p.llWatcher.Source()),
			stringToHTML(string(s.p.llWatcher.LastJSON())),
		}
		wd, err := os.Getwd()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t, err := template.ParseFiles(wd + "/submission/view/info.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		t.Execute(w, data)
	}
}