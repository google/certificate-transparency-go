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

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
)

// CTPolicyType indicates CT-policy used for certificate submission.
type CTPolicyType int

// Policy type values:
const (
	ChromeCTPolicy CTPolicyType = iota
	AppleCTPolicy
)

// getDistributor given CT-policy type produces corresponding Distributor constructor.
func getDistributor(plc CTPolicyType) func(*loglist.LogList) (*Distributor, error) {
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
	logListPath          string
	llRefreshInterval    time.Duration
	rootsRefreshInterval time.Duration
	ctPlc                CTPolicyType

	llWatcher *LogListRefresher

	mu   sync.RWMutex // guards the distributor
	dist *Distributor
}

// NewProxy creates and inits a Proxy instance.
func NewProxy(ctx context.Context, llPath string, llRefresh time.Duration, rootsRefresh time.Duration, ctPlc CTPolicyType) *Proxy {
	var p Proxy
	p.logListPath = llPath
	p.llRefreshInterval = llRefresh
	p.rootsRefreshInterval = rootsRefresh
	p.ctPlc = ctPlc
	p.llWatcher = NewLogListRefresher(llPath)

	go Every(ctx, p.llRefreshInterval, func(ctx context.Context) {
		p.RefreshLogList(ctx)
	})

	return &p
}

// RefreshLogList reads Log List one time and runs updates if necessary.
func (p *Proxy) RefreshLogList(ctx context.Context) {
	// single LogList refresh.
	if p.llWatcher == nil {
		return
	}
	if ll, err := p.llWatcher.Refresh(); err != nil {
		glog.Error(err)
	} else {
		p.RestartDistributor(ctx, ll)
	}
}

// RestartDistributor activates new Distributor instance with Log List provided
// and sets it as active.
func (p *Proxy) RestartDistributor(ctx context.Context, ll *loglist.LogList) error {
	d, err := getDistributor(p.ctPlc)(ll)
	if err != nil {
		// losing ll info.
		return err
	}

	// Start refreshing roots periodically so they stay up-to-date.
	go Every(ctx, p.rootsRefreshInterval, func(ctx context.Context) {
		if errs := d.RefreshRoots(ctx); len(errs) > 0 {
			glog.Error(errs)
		}
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	p.dist = d
	return nil
}

// AddPreChain passes call to underlying Distributor instance.
func (p *Proxy) AddPreChain(ctx context.Context, rawChain [][]byte) ([]*AssignedSCT, error) {
	if p.dist == nil {
		return []*AssignedSCT{}, fmt.Errorf("proxy distributor is not initialized")
	}
	return p.dist.AddPreChain(ctx, rawChain)
}
