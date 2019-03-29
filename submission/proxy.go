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
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/schedule"
)

// CTPolicyType indicates CT-policy used for certificate submission.
type CTPolicyType int

// Policy type values:
const (
	ChromeCTPolicy CTPolicyType = iota
	AppleCTPolicy
)

// DistributorFactory is building Distributor c-tor given CTPolicyType.
type DistributorFactory interface {
	GetDistributorBuilder(plc CTPolicyType) func(*loglist.LogList) (*Distributor, error)
}

// DefaultDistributorFactory builds standard production Distributors.
type DefaultDistributorFactory struct {
}

// getDistributorBuilder given CT-policy type produces Distributor c-tor.
func (*DefaultDistributorFactory) GetDistributorBuilder(plc CTPolicyType) func(*loglist.LogList) (*Distributor, error) {
	if plc == AppleCTPolicy {
		return func(ll *loglist.LogList) (*Distributor, error) {
			return NewDistributor(ll, ctpolicy.AppleCTPolicy{}, BuildLogClient)
		}
	}
	return func(ll *loglist.LogList) (*Distributor, error) {
		return NewDistributor(ll, ctpolicy.ChromeCTPolicy{}, BuildLogClient)
	}
}

// Proxy wraps Log List updates watcher and Distributor running on fresh Log List.
type Proxy struct {
	Errors chan error

	llRefreshInterval    time.Duration
	rootsRefreshInterval time.Duration
	ctPlc                CTPolicyType

	llWatcher          LogListRefresher
	distributorFactory DistributorFactory

	distMu     sync.RWMutex // guards the distributor
	dist       *Distributor
	distCancel context.CancelFunc // used to cancel distributor updates
}

// NewProxy creates an inactive Proxy instance. Call Run() to activate.
func NewProxy(llr LogListRefresher, df DistributorFactory, ctPlc CTPolicyType) *Proxy {
	var p Proxy
	p.llWatcher = llr
	p.distributorFactory = df
	p.ctPlc = ctPlc
	p.Errors = make(chan error, 1)
	p.rootsRefreshInterval = 24 * time.Hour

	return &p
}

// Run starts regular LogList checks and associated Distributor initialization.
func (p *Proxy) Run(ctx context.Context, llRefresh time.Duration, rootsRefresh time.Duration) {
	p.llRefreshInterval = llRefresh
	p.rootsRefreshInterval = rootsRefresh
	go schedule.Every(ctx, p.llRefreshInterval, func(ctx context.Context) {
		if err := p.RefreshLogList(ctx); err != nil {
			p.Errors <- err
		}
	})
}

// RefreshLogList reads Log List one time and runs updates if necessary.
func (p *Proxy) RefreshLogList(ctx context.Context) error {
	if p.llWatcher == nil {
		return fmt.Errorf("proxy has no log-list watcher to refresh Log List")
	}
	ll, err := p.llWatcher.Refresh()
	if err != nil {
		return err
	}
	if err = p.restartDistributor(ctx, ll); err != nil {
		p.Errors <- err
	}
	return nil
}

// restartDistributor activates new Distributor instance with Log List provided
// and sets it as active.
func (p *Proxy) restartDistributor(ctx context.Context, ll *loglist.LogList) error {
	d, err := p.distributorFactory.GetDistributorBuilder(p.ctPlc)(ll)
	if err != nil {
		// losing ll info. No good.
		return err
	}

	// Start refreshing roots periodically so they stay up-to-date.
	refreshCtx, refreshCancel := context.WithCancel(ctx)
	go schedule.Every(refreshCtx, p.rootsRefreshInterval, func(ectx context.Context) {
		if errs := d.RefreshRoots(ectx); len(errs) > 0 {
			for logURL, err := range errs {
				p.Errors <- fmt.Errorf("proxy on %q got %v", logURL, err)
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
func (p *Proxy) AddPreChain(ctx context.Context, rawChain [][]byte) ([]*AssignedSCT, error) {
	if p.dist == nil {
		return []*AssignedSCT{}, fmt.Errorf("proxy distributor is not initialized. call Run()")
	}
	return p.dist.AddPreChain(ctx, rawChain)
}
