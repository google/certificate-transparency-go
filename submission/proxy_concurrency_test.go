// Copyright 2026 Lucas Coelho. All Rights Reserved.
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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/trillian/monitoring"
)

// Keep root refreshes from installing an empty root pool while submissions run.
// AddChain and AddPreChain still return the normal synthetic SCTs.
type concurrencyStubLogClient struct {
	stubLogClient
}

func (c concurrencyStubLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	return stubNoRootsLogClient{}.GetAcceptedRoots(ctx)
}

func newConcurrencyStubLogClient(log *loglist3.Log) (client.AddLogClient, error) {
	return concurrencyStubLogClient{stubLogClient{logURL: log.URL, rootsCerts: map[string][]rootInfo{log.URL: {}}}}, nil
}

func newConcurrencyDistributor(ll *loglist3.LogList) (*Distributor, error) {
	return NewDistributor(ll, buildStubCTPolicy(1), newConcurrencyStubLogClient, imf)
}

type blockingStubLogClient struct {
	stubLogClient
	started chan struct{}
	release chan struct{}
	once    *sync.Once
}

func (b *blockingStubLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	return nil, context.Canceled
}

func (b *blockingStubLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.stubLogClient.AddChain(ctx, chain)
}

func TestProxyConcurrentReloadAndAddChain(t *testing.T) {
	ll1 := sampleValidLogList()
	ll2 := sampleValidLogList()
	ll2.Version = "3.2"

	p := NewProxy(stubLogListManager(), newConcurrencyDistributor, imf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed initial distributor so AddChain/AddPreChain execute active submissions.
	if err := p.restartDistributor(ctx, ll1); err != nil {
		t.Fatalf("initial restartDistributor: %v", err)
	}

	chain := pemFileToDERChain("../trillian/testdata/subleaf.chain")
	preChain := pemFileToDERChain("../trillian/testdata/subleaf-pre.chain")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			ll := ll1
			if i%2 == 1 {
				ll = ll2
			}
			if err := p.restartDistributor(ctx, ll); err != nil {
				t.Errorf("restartDistributor(%d): %v", i, err)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if (id+i)%2 == 0 {
					if _, err := p.AddChain(ctx, chain, false); err != nil {
						t.Errorf("AddChain: %v", err)
					}
				} else {
					if _, err := p.AddPreChain(ctx, preChain, false); err != nil {
						t.Errorf("AddPreChain: %v", err)
					}
				}
			}
		}(g)
	}

	wg.Wait()
}

func TestProxyOldDistributorRefreshCancelDoesNotBreakActiveAddChain(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var startedOnce sync.Once

	lcBuilder := func(log *loglist3.Log) (client.AddLogClient, error) {
		base := stubLogClient{logURL: log.URL, rootsCerts: map[string][]rootInfo{log.URL: {}}}
		if calls.Add(1) <= 3 {
			return &blockingStubLogClient{
				stubLogClient: base,
				started:       started,
				release:       release,
				once:          &startedOnce,
			}, nil
		}
		return base, nil
	}

	dBuilder := func(ll *loglist3.LogList) (*Distributor, error) {
		return NewDistributor(ll, buildStubCTPolicy(1), lcBuilder, imf)
	}
	p := NewProxy(stubLogListManager(), dBuilder, imf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ll := sampleValidLogList()
	if err := p.restartDistributor(ctx, ll); err != nil {
		t.Fatalf("initial restartDistributor: %v", err)
	}

	chain := pemFileToDERChain("../trillian/testdata/subleaf.chain")
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()

	type addRes struct {
		scts []*AssignedSCT
		err  error
	}
	resCh := make(chan addRes, 1)
	go func() {
		scts, err := p.AddChain(reqCtx, chain, false)
		resCh <- addRes{scts: scts, err: err}
	}()

	// Wait until the active request is inside the first distributor's log client.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for active AddChain to enter blockingStubLogClient")
	}

	// Replace distributor (which cancels old refreshCtx). Active request must still succeed.
	if err := p.restartDistributor(ctx, ll); err != nil {
		t.Fatalf("replacement restartDistributor: %v", err)
	}
	close(release)

	select {
	case res := <-resCh:
		if res.err != nil || len(res.scts) == 0 {
			t.Fatalf("expected active AddChain on replaced distributor to succeed, got scts=%d err=%v", len(res.scts), res.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for active AddChain completion")
	}
}

func TestProxyServerHandleInfoUninitialized(t *testing.T) {
	ps := NewProxyServer("nonexistent", newConcurrencyDistributor, time.Second, monitoring.InertMetricFactory{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	ps.HandleInfo(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("HandleInfo uninitialized status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestProxyServerConcurrentHandleRequestsDuringRun(t *testing.T) {
	llBytes, err := json.Marshal(sampleValidLogList())
	if err != nil {
		t.Fatalf("marshal log list: %v", err)
	}
	llSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		_, _ = w.Write(llBytes)
	}))
	defer llSrv.Close()

	ps := NewProxyServer(llSrv.URL, newConcurrencyDistributor, 2*time.Second, monitoring.InertMetricFactory{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		ps.Run(ctx, time.Hour, time.Hour, true)
	}()
	var wg sync.WaitGroup

	chain := pemFileToDERChain("../trillian/testdata/subleaf.chain")
	body, err := json.Marshal(ct.AddChainRequest{Chain: chain})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				rr := httptest.NewRecorder()
				ps.HandleInfo(rr, req)
				if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
					t.Errorf("unexpected HandleInfo status %d", rr.Code)
				}
			} else {
				req := httptest.NewRequest(http.MethodPost, "/ct/v1/proxy/add-chain/", bytes.NewReader(body))
				rr := httptest.NewRecorder()
				ps.HandleAddChain(rr, req)
				if rr.Code != http.StatusBadGateway && rr.Code != http.StatusOK {
					t.Errorf("unexpected HandleAddChain status %d: %s", rr.Code, rr.Body.String())
				}
			}
			time.Sleep(3 * time.Millisecond)
		}(i)
	}
	wg.Wait()
	select {
	case <-runDone:
		if ctx.Err() != nil {
			t.Fatalf("Run did not initialize before timeout: %v", ctx.Err())
		}
	case <-ctx.Done():
		t.Fatalf("Run did not initialize: %v", ctx.Err())
	}
	rr := httptest.NewRecorder()
	ps.HandleAddChain(rr, httptest.NewRequest(http.MethodPost, "/ct/v1/proxy/add-chain/", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("initialized HandleAddChain status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}
