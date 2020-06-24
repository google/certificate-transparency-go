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
	"github.com/google/trillian/monitoring"
)

// ProxyServer wraps Proxy and handles HTTP-requests for it.
type ProxyServer struct {
	p               *Proxy
	addTimeout      time.Duration
	loadPendingLogs bool
}

// NewProxyServer creates ProxyServer instance. Call Run() to init.
func NewProxyServer(logListPath string, dBuilder DistributorBuilder, reqTimeout time.Duration, mf monitoring.MetricFactory) *ProxyServer {
	s := &ProxyServer{addTimeout: reqTimeout}
	s.p = NewProxy(NewLogListManager(NewLogListRefresher(logListPath), mf), dBuilder, mf)
	return s
}

// Run starts regular Log list updates in the background, running until the
// context is canceled. Blocks until initialization happens.
func (s *ProxyServer) Run(ctx context.Context, logListRefreshInterval time.Duration, rootsRefreshInterval time.Duration, loadPendingLogs bool) {
	s.loadPendingLogs = loadPendingLogs
	s.p.Run(ctx, logListRefreshInterval, rootsRefreshInterval)

	<-s.p.Init
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

// handleAddSomeChain is helper func choosing between AddChain and AddPreChain
// based on asPreChain value
func (s *ProxyServer) handleAddSomeChain(w http.ResponseWriter, r *http.Request, asPreChain bool) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	addChainReq, err := ctfe.ParseBodyAsJSONChain(r)
	if err != nil {
		rc := http.StatusBadRequest
		pre := ""
		if asPreChain {
			pre = "pre-"
		}
		http.Error(w, fmt.Sprintf("proxy: failed to parse add-%schain body: %s", pre, err), rc)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.addTimeout)
	defer cancel()

	var scts []*AssignedSCT
	if asPreChain {
		scts, err = s.p.AddPreChain(ctx, addChainReq.Chain, s.loadPendingLogs)
	} else {
		scts, err = s.p.AddChain(ctx, addChainReq.Chain, s.loadPendingLogs)
	}
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

// HandleAddPreChain handles multiplexed add-pre-chain HTTP request.
func (s *ProxyServer) HandleAddPreChain(w http.ResponseWriter, r *http.Request) {
	s.handleAddSomeChain(w, r, true /* asPreChain*/)
}

// HandleAddChain handles multiplexed add-chain HTTP request.
func (s *ProxyServer) HandleAddChain(w http.ResponseWriter, r *http.Request) {
	s.handleAddSomeChain(w, r, false /* asPreChain*/)
}

func stringToHTML(s string) template.HTML {
	return template.HTML(strings.Replace(template.HTMLEscapeString(string(s)), "\n", "<br>", -1))
}

// InfoData wraps data field required for info-page.
type InfoData struct {
	PolicyName  string
	LogListPath template.HTML
	LogListJSON template.HTML
}

// HandleInfo handles info-page request.
func (s *ProxyServer) HandleInfo(w http.ResponseWriter, r *http.Request) {
	data := InfoData{
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
