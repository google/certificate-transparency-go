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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
)

const (
	// RootsRefreshInterval is roots refresh interval.
	RootsRefreshInterval = time.Hour * 24
)

// Distributor class operates policy-based submission across Logs.
type Distributor struct {
	ll *loglist.LogList

	mu sync.RWMutex

	// helper structs produced out of ll during init.
	logClients map[string]client.AddLogClient
	logRoots   loglist.LogRoots
	rootPool   *ctfe.PEMCertPool

	rootsRefreshTicker *time.Ticker

	policy ctpolicy.CTPolicy
}

// Run starts regular roots updates.
func (d *Distributor) run() {
	d.rootsRefreshTicker = time.NewTicker(RootsRefreshInterval)
	go func() {
		for range d.rootsRefreshTicker.C {
			d.refreshRoots(context.Background())
		}
	}()
}

// refreshRoots requests roots from Logs and updates local copy if necessary.
func (d *Distributor) refreshRoots(ctx context.Context) []error {
	// TODO(Mercurrent) add implementation.
	var errors []error
	return errors
}

// SubmitToLog is Submitter interface.
func (d *Distributor) SubmitToLog(ctx context.Context, logURL string, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	// TODO(Mercurrent) add implementation.
	return nil, nil
}

// AddPreChain runs add-pre-chain calls across subset of logs according to
// Distributor's policy. May emit both SCTs array and error when SCTs
// collected do not satisfy the policy.
func (d *Distributor) AddPreChain(ctx context.Context, rawChain [][]byte) ([]*AssignedSCT, error) {
	// TODO(Mercurrent) add implementation.
	return []*AssignedSCT{}, nil
}

// LogClientBuilder builds client-interface instance for a given Log.
type LogClientBuilder func(*loglist.Log) (client.AddLogClient, error)

// BuildLogClient is default (non-mock) LogClientBuilder.
func buildLogClient(log *loglist.Log) (client.AddLogClient, error) {
	url := log.URL
	if !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	hc := &http.Client{Timeout: time.Second * 10}
	return client.New(url, hc, jsonclient.Options{PublicKeyDER: log.Key})
}

// NewDistributor creates and inits a Distributor instance. May return both
// the instance and errors when any of logs were unable to response on
// the first root-collection phase.
// Fails iff any Log couldn't get its client built.
func NewDistributor(ll *loglist.LogList, plc ctpolicy.CTPolicy, lcBuilder LogClientBuilder) (*Distributor, error) {
	var d Distributor
	active := ll.ActiveLogs()
	d.ll = &active
	d.policy = plc
	d.logClients = make(map[string]client.AddLogClient)
	d.logRoots = make(loglist.LogRoots)

	// Build clients for each of the Logs.
	for _, log := range ll.Logs {
		lc, err := lcBuilder(&log)
		if err != nil {
			return nil, fmt.Errorf("Failed to create log client for %s: %v", log.URL, err)
		}
		d.logClients[log.URL] = lc
	}
	// Collect Log-roots.
	errs := d.refreshRoots(context.Background())

	// Set up regular roots updates.
	d.run()

	if len(errs) > 0 {
		return &d, fmt.Errorf("not all log-roots collected: %v", errs)
	}
	return &d, nil
}
