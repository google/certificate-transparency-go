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
	"net/url"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
)

const (
	// RootsRefreshInterval is interval between consecutive get-roots calls.
	rootsRefreshInterval = time.Hour * 24
)

// Distributor operates policy-based submission across Logs.
type Distributor struct {
	ll *loglist.LogList

	// helper structs produced out of ll during init.
	logClients map[string]client.AddLogClient
	logRoots   loglist.LogRoots
	rootPool   *ctfe.PEMCertPool

	rootsRefreshTicker *time.Ticker

	policy ctpolicy.CTPolicy
}

// Run starts regular roots updates.
func (d *Distributor) Run(ctx context.Context) {
	if d.rootsRefreshTicker != nil {
		return
	}
	// Collect Log-roots first time.
	go func() {
		d.refreshRoots(ctx)
	}()

	d.rootsRefreshTicker = time.NewTicker(rootsRefreshInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				d.rootsRefreshTicker = nil
				return
			case <-d.rootsRefreshTicker.C:
				d.refreshRoots(ctx)
			}
		}
	}()
}

// refreshRoots requests roots from Logs and updates local copy if necessary.
func (d *Distributor) refreshRoots(ctx context.Context) {
	// TODO(Mercurrent) add implementation.
}

// SubmitToLog is races-Submitter interface.
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
func BuildLogClient(log *loglist.Log) (client.AddLogClient, error) {
	url, err := url.Parse(log.URL)
	if err != nil {
		return nil, err
	}
	if url.Scheme == "" {
		url.Scheme = "https"
	}
	hc := &http.Client{Timeout: time.Second * 10}
	return client.New(url.String(), hc, jsonclient.Options{PublicKeyDER: log.Key})
}

// NewDistributor creates and inits a Distributor instance.
// The Distributor will asynchronously fetch the latest roots from all of the
// logs when active. Call Run() to fetch roots and init regular updates to keep
// the local copy of the roots up-to-date.
func NewDistributor(ll *loglist.LogList, plc ctpolicy.CTPolicy, lcBuilder LogClientBuilder) (*Distributor, error) {
	var d Distributor
	active := ll.ActiveLogs()
	d.ll = &active
	d.policy = plc
	d.logClients = make(map[string]client.AddLogClient)
	d.logRoots = make(loglist.LogRoots)

	// Build clients for each of the Logs.
	for _, log := range d.ll.Logs {
		lc, err := lcBuilder(&log)
		if err != nil {
			return nil, fmt.Errorf("failed to create log client for %s: %v", log.URL, err)
		}
		d.logClients[log.URL] = lc
	}
	return &d, nil
}
