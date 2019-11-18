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

// Package submission contains code and structs for certificates submission proxy.
package submission

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian/monitoring"
)

// CTPolicyType indicates CT-policy used for certificate submission.
type CTPolicyType int

// Policy type values:
const (
	ChromeCTPolicy CTPolicyType = iota
	AppleCTPolicy
)

var (
	proxyOnce      sync.Once
	logListUpdates monitoring.Counter
	rspLatency     monitoring.Histogram // ep => value
)

// proxyInitMetrics initializes all the exported metrics.
func proxyInitMetrics(mf monitoring.MetricFactory) {
	logListUpdates = mf.NewCounter("log_list_updates", "Number of Log-list updates")
	rspLatency = mf.NewHistogram("http_latency", "Latency of policy-multiplexed add-responses in seconds", "ep")
}

// DistributorBuilder builds distributor instance for a given Log list.
type DistributorBuilder func(*loglist2.LogList) (*Distributor, error)

// GetDistributorBuilder given CT-policy type and Log-client builder produces
// Distributor c-tor.
func GetDistributorBuilder(plc CTPolicyType, lcBuilder LogClientBuilder, mf monitoring.MetricFactory) DistributorBuilder {
	if plc == AppleCTPolicy {
		return func(ll *loglist2.LogList) (*Distributor, error) {
			return NewDistributor(ll, ctpolicy.AppleCTPolicy{}, lcBuilder, mf)
		}
	}
	return func(ll *loglist2.LogList) (*Distributor, error) {
		return NewDistributor(ll, ctpolicy.ChromeCTPolicy{}, lcBuilder, mf)
	}
}

// ASN1MarshalSCTs serializes list of AssignedSCTs according to RFC6962 3.3
func ASN1MarshalSCTs(scts []*AssignedSCT) ([]byte, error) {
	if len(scts) == 0 {
		return nil, fmt.Errorf("ASN1MarshalSCTs requires positive number of SCTs, 0 provided")
	}
	unassignedSCTs := make([]*ct.SignedCertificateTimestamp, 0, len(scts))
	for _, sct := range scts {
		unassignedSCTs = append(unassignedSCTs, sct.SCT)
	}
	sctList, err := x509util.MarshalSCTsIntoSCTList(unassignedSCTs)
	if err != nil {
		return nil, err
	}
	encdSCTList, err := tls.Marshal(*sctList)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(encdSCTList)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// Proxy wraps Log List updates watcher and Distributor running on fresh Log List.
type Proxy struct {
	Init chan bool

	llRefreshInterval    time.Duration
	rootsRefreshInterval time.Duration

	llWatcher          *LogListManager
	distributorBuilder DistributorBuilder

	distMu     sync.RWMutex // guards the distributor
	dist       *Distributor
	distCancel context.CancelFunc // used to cancel distributor updates
}

// NewProxy creates an inactive Proxy instance. Call Run() to activate.
func NewProxy(llm *LogListManager, db DistributorBuilder, mf monitoring.MetricFactory) *Proxy {
	var p Proxy
	p.llWatcher = llm
	p.distributorBuilder = db
	p.Init = make(chan bool, 1)
	p.rootsRefreshInterval = 24 * time.Hour

	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	proxyOnce.Do(func() { proxyInitMetrics(mf) })

	return &p
}

// Run starts regular LogList checks and associated Distributor initialization.
// Sends true via Init channel when init is complete.
// Terminates upon context cancellation.
func (p *Proxy) Run(ctx context.Context, llRefresh time.Duration, rootsRefresh time.Duration) {
	init := false
	p.llRefreshInterval = llRefresh
	p.rootsRefreshInterval = rootsRefresh
	p.llWatcher.Run(ctx, llRefresh)

	go func() {
		for {
			select {
			case <-ctx.Done():
				if !init {
					close(p.Init)
				}
				return
			case llData := <-p.llWatcher.LLUpdates:
				logListUpdates.Inc()
				if err := p.restartDistributor(ctx, llData.List); err != nil {
					glog.Errorf("Unable to use Log-list:\n %v\n %v", err, llData.JSON)
				} else if !init {
					init = true
					p.Init <- true
					close(p.Init)
				}
			case err := <-p.llWatcher.Errors:
				glog.Error(err)
			}
		}
	}()
}

// restartDistributor activates new Distributor instance with Log List provided
// and sets it as active.
func (p *Proxy) restartDistributor(ctx context.Context, ll *loglist2.LogList) error {
	d, err := p.distributorBuilder(ll)
	if err != nil {
		// losing ll info. No good.
		return err
	}

	// Start refreshing roots periodically so they stay up-to-date.
	refreshCtx, refreshCancel := context.WithCancel(ctx)
	go schedule.Every(refreshCtx, p.rootsRefreshInterval, func(ectx context.Context) {
		if errs := d.RefreshRoots(ectx); len(errs) > 0 {
			for _, err := range errs {
				glog.Warning(err)
			}
		}
	})

	p.distMu.Lock()
	defer p.distMu.Unlock()
	if p.distCancel != nil {
		p.distCancel()
	}
	p.dist = d
	p.distCancel = refreshCancel
	return nil
}

// AddPreChain passes call to underlying Distributor instance.
func (p *Proxy) AddPreChain(ctx context.Context, rawChain [][]byte, loadPendingLogs bool) ([]*AssignedSCT, error) {
	if p.dist == nil {
		return []*AssignedSCT{}, fmt.Errorf("proxy distributor is not initialized. call Run()")
	}

	defer func(start time.Time) {
		rspLatency.Observe(time.Since(start).Seconds(), "add-pre-chain")
	}(time.Now())
	return p.dist.AddPreChain(ctx, rawChain, loadPendingLogs)
}

// AddChain passes call to underlying Distributor instance.
func (p *Proxy) AddChain(ctx context.Context, rawChain [][]byte, loadPendingLogs bool) ([]*AssignedSCT, error) {
	if p.dist == nil {
		return []*AssignedSCT{}, fmt.Errorf("proxy distributor is not initialized. call Run()")
	}
	defer func(start time.Time) {
		rspLatency.Observe(time.Since(start).Seconds(), "add-chain")
	}(time.Now())
	return p.dist.AddChain(ctx, rawChain, loadPendingLogs)
}
