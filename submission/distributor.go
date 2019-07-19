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
	"strconv"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/monitoring"

	ct "github.com/google/certificate-transparency-go"
)

var (
	// Metrics are per-log, per-endpoint and some per-response-status code.
	distOnce    sync.Once
	reqsCounter monitoring.Counter   // logurl, ep => value
	rspsCounter monitoring.Counter   // logurl, ep, sc => value
	rspLatency  monitoring.Histogram // logurl, ep => value
)

// distInitMetrics initializes all the exported metrics.
func distInitMetrics(mf monitoring.MetricFactory) {
	reqsCounter = mf.NewCounter("http_reqs", "Number of requests", "logurl", "ep")
	rspsCounter = mf.NewCounter("http_rsps", "Number of responses", "logurl", "ep", "httpstatus")
	rspLatency = mf.NewHistogram("http_latency", "Latency of responses in seconds", "logurl", "ep")
}

const (
	// GetRootsTimeout timeout used for external requests within root-updates.
	getRootsTimeout = time.Second * 10
)

// Distributor operates policy-based submission across Logs.
type Distributor struct {
	ll *loglist.LogList

	mu sync.RWMutex

	// helper structs produced out of ll during init.
	logClients map[string]client.AddLogClient
	logRoots   loglist.LogRoots
	rootPool   *ctfe.PEMCertPool

	rootDataFull bool

	policy ctpolicy.CTPolicy
}

// RefreshRoots requests roots from Logs and updates local copy.
// Returns error map keyed by log-URL for any Log experiencing roots retrieval
// problems
// If at least one root was successfully parsed for a log, log roots set gets
// the update.
func (d *Distributor) RefreshRoots(ctx context.Context) map[string]error {
	type RootsResult struct {
		LogURL string
		Roots  *ctfe.PEMCertPool
		Err    error
	}
	ch := make(chan RootsResult, len(d.logClients))

	rctx, cancel := context.WithTimeout(ctx, getRootsTimeout)
	defer cancel()

	for logURL, lc := range d.logClients {
		go func(logURL string, lc client.AddLogClient) {
			res := RootsResult{LogURL: logURL}

			roots, err := lc.GetAcceptedRoots(rctx)
			if err != nil {
				res.Err = fmt.Errorf("roots refresh for %s: couldn't collect roots. %s", logURL, err)
				ch <- res
				return
			}
			res.Roots = ctfe.NewPEMCertPool()
			for _, r := range roots {
				parsed, err := x509.ParseCertificate(r.Data)
				if x509.IsFatal(err) {
					errS := fmt.Errorf("roots refresh for %s: unable to parse root cert: %s", logURL, err)
					if res.Err != nil {
						res.Err = fmt.Errorf("%s\n%s", res.Err, errS)
					} else {
						res.Err = errS
					}
					continue
				}
				res.Roots.AddCert(parsed)
			}
			ch <- res
		}(logURL, lc)
	}

	// Collect get-roots results for every Log-client.
	freshRoots := make(loglist.LogRoots)
	errors := make(map[string]error)
	for range d.logClients {
		r := <-ch
		// update roots
		if r.Err != nil {
			errors[r.LogURL] = r.Err
		}
		// Roots get update even if some returned roots couldn't get parsed.
		if r.Roots != nil {
			freshRoots[r.LogURL] = r.Roots
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.logRoots = freshRoots
	d.rootDataFull = len(d.logRoots) == len(d.logClients)
	// Merge individual root-pools into a unified one
	d.rootPool = ctfe.NewPEMCertPool()
	for _, pool := range d.logRoots {
		for _, c := range pool.RawCertificates() {
			d.rootPool.AddCert(c)
		}
	}

	return errors
}

// IsRootDataFull returns true if root certificates have been obtained for all Logs.
func (d *Distributor) isRootDataFull() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.rootDataFull
}

// incRspsCounter extracts HTTP status code and increments corresponding rspsCounter.
func incRspsCounter(logURL string, endpoint string, rspErr error) {
	status := http.StatusOK
	if rspErr != nil {
		status = http.StatusBadRequest // default to this if status code unavailable
		if err, ok := rspErr.(client.RspError); ok {
			status = err.StatusCode
		}
	}
	rspsCounter.Inc(logURL, endpoint, strconv.Itoa(status))
}

// SubmitToLog implements Submitter interface.
func (d *Distributor) SubmitToLog(ctx context.Context, logURL string, chain []ct.ASN1Cert, asPreChain bool) (*ct.SignedCertificateTimestamp, error) {
	lc, ok := d.logClients[logURL]
	if !ok {
		return nil, fmt.Errorf("no client registered for Log with URL %q", logURL)
	}

	// endpoint used for metrics
	endpoint := string(ctfe.AddChainName)
	if asPreChain {
		endpoint = string(ctfe.AddPreChainName)
	}

	defer func(start time.Time) {
		rspLatency.Observe(time.Since(start).Seconds(), logURL, endpoint)
	}(time.Now())
	reqsCounter.Inc(logURL, endpoint)
	addChain := lc.AddChain
	if asPreChain {
		addChain = lc.AddPreChain
	}
	sct, err := addChain(ctx, chain)
	incRspsCounter(logURL, endpoint, err)
	return sct, err
}

// parseRawChain reads cert chain from bytes into x509.Certificate format.
func parseRawChain(rawChain [][]byte) ([]*x509.Certificate, error) {
	parsedChain := make([]*x509.Certificate, 0, len(rawChain))
	for _, certBytes := range rawChain {
		cert, err := x509.ParseCertificate(certBytes)
		if x509.IsFatal(err) {
			return nil, fmt.Errorf("distributor unable to parse cert-chain %v", err)
		}
		parsedChain = append(parsedChain, cert)
	}
	return parsedChain, nil
}

// addSomeChain is helper calling one of AddChain or AddPreChain based
// on asPreChain param.
func (d *Distributor) addSomeChain(ctx context.Context, rawChain [][]byte, asPreChain bool) ([]*AssignedSCT, error) {
	if len(rawChain) == 0 {
		return nil, fmt.Errorf("distributor unable to process empty chain")
	}

	var parsedChain []*x509.Certificate
	var compatibleLogs loglist.LogList

	d.mu.RLock()
	vOpts := ctfe.NewCertValidationOpts(d.rootPool, time.Time{}, false, false, nil, nil, false, nil)
	rootedChain, err := ctfe.ValidateChain(rawChain, vOpts)

	if err == nil {
		parsedChain = rootedChain
		compatibleLogs = d.ll.Compatible(rootedChain[0], rootedChain[len(rootedChain)-1], d.logRoots)
	} else if d.isRootDataFull() {
		// Could not verify the chain while root info for logs is complete.
		d.mu.RUnlock()
		return nil, fmt.Errorf("distributor unable to process cert-chain: %v", err)
	} else {
		// Chain might be rooted to the Log which has no root-info yet.
		parsedChain, err = parseRawChain(rawChain)
		if err != nil {
			return nil, fmt.Errorf("distributor unable to parse cert-chain: %v", err)
		}
		compatibleLogs = d.ll.Compatible(parsedChain[0], nil, d.logRoots)
	}
	d.mu.RUnlock()

	// Distinguish between precerts and certificates.
	isPrecert, err := ctfe.IsPrecertificate(parsedChain[0])
	if err != nil {
		return nil, fmt.Errorf("distributor unable to check certificate %v: \n%v", parsedChain[0], err)
	}
	if isPrecert != asPreChain {
		var methodType, inputType string
		if asPreChain {
			methodType = "pre-"
		}
		if isPrecert {
			inputType = "pre-"
		}
		return nil, fmt.Errorf("add-%schain method expected %scertificate, got %scertificate", methodType, methodType, inputType)
	}

	// Set up policy structs.
	groups, err := d.policy.LogsByGroup(parsedChain[0], &compatibleLogs)
	if err != nil {
		return nil, fmt.Errorf("distributor does not have enough compatible Logs to comply with the policy: %v", err)
	}
	chain := make([]ct.ASN1Cert, len(parsedChain))
	for i, c := range parsedChain {
		chain[i] = ct.ASN1Cert{Data: c.Raw}
	}
	return GetSCTs(ctx, d, chain, asPreChain, groups)
}

// AddPreChain runs add-pre-chain calls across subset of logs according to
// Distributor's policy. May emit both SCTs array and error when SCTs
// collected do not satisfy the policy.
func (d *Distributor) AddPreChain(ctx context.Context, rawChain [][]byte) ([]*AssignedSCT, error) {
	return d.addSomeChain(ctx, rawChain, true)
}

// AddChain runs add-chain calls across subset of logs according to
// Distributor's policy. May emit both SCTs array and error when SCTs
// collected do not satisfy the policy.
func (d *Distributor) AddChain(ctx context.Context, rawChain [][]byte) ([]*AssignedSCT, error) {
	return d.addSomeChain(ctx, rawChain, false)
}

// LogClientBuilder builds client-interface instance for a given Log.
type LogClientBuilder func(*loglist.Log) (client.AddLogClient, error)

// BuildLogClient is default (non-mock) LogClientBuilder.
func BuildLogClient(log *loglist.Log) (client.AddLogClient, error) {
	u, err := url.Parse(log.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	hc := &http.Client{Timeout: time.Second * 10}
	return client.New(u.String(), hc, jsonclient.Options{PublicKeyDER: log.Key})
}

// NewDistributor creates and inits a Distributor instance.
// The Distributor will asynchronously fetch the latest roots from all of the
// logs when active. Call Run() to fetch roots and init regular updates to keep
// the local copy of the roots up-to-date.
func NewDistributor(ll *loglist.LogList, plc ctpolicy.CTPolicy, lcBuilder LogClientBuilder, mf monitoring.MetricFactory) (*Distributor, error) {
	var d Distributor
	active := ll.ActiveLogs()
	d.ll = &active
	d.policy = plc
	d.logClients = make(map[string]client.AddLogClient)
	d.logRoots = make(loglist.LogRoots)
	d.rootPool = ctfe.NewPEMCertPool()

	// Build clients for each of the Logs. Also build log-to-id map.
	for _, log := range d.ll.Logs {
		lc, err := lcBuilder(&log)
		if err != nil {
			return nil, fmt.Errorf("failed to create log client for %s: %v", log.URL, err)
		}
		d.logClients[log.URL] = lc
	}
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	distOnce.Do(func() { distInitMetrics(mf) })
	return &d, nil
}
