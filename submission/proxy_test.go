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
	"os"
	"regexp"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/testdata"
)

func TestProxyNoLLWatcher(t *testing.T) {
	p := NewProxy(nil, GetDistributorBuilder(ChromeCTPolicy, buildStubLogClient))
	err := p.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("p.RefreshLogList() on nil LogListRefresher expected to get error, got none")
	}
}

func TestProxyNoLLWatcherAfterRun(t *testing.T) {
	p := NewProxy(nil, GetDistributorBuilder(ChromeCTPolicy, buildStubLogClient))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p.Run(ctx, 3*time.Second, 3*time.Second)
	select {
	case <-p.Errors:
		return
	case <-ctx.Done():
		t.Errorf("p.Run() on nil LogListRefresher expected to emit error, got none")
	}
}

// stubLogListRefresher produces error on each Refresh call.
type stubLogListRefresher struct {
}

func (llr stubLogListRefresher) Refresh() (*loglist.LogList, error) {
	return nil, fmt.Errorf("stub Log List Refresher produces no Log List")
}

func TestProxyRefreshLLErr(t *testing.T) {
	p := NewProxy(stubLogListRefresher{}, GetDistributorBuilder(ChromeCTPolicy, buildStubLogClient))

	err := p.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("p.RefreshLogList() on stubLogListRefresher expected to get error, got none")
	}
}

func TestProxyBrokenDistributor(t *testing.T) {
	p := NewProxy(stubLogListRefresher{}, GetDistributorBuilder(ChromeCTPolicy, buildNoLogClient))

	err := p.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("p.RefreshLogList() on brokenDistributorFactory expected to get error, got none")
	}
}

// Stub for AddLogCLient interface
type stubNoRootsLogClient struct {
	logURL string
}

func (m stubNoRootsLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, fmt.Errorf("log %q has no roots", m.logURL)
}

func (m stubNoRootsLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, fmt.Errorf("log %q has no roots", m.logURL)
}

func (m stubNoRootsLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	//fmt.Printf("No roots get accepted roots")
	return nil, fmt.Errorf("stubNoRootsLogClient cannot provide roots")
}

func buildStubNoRootsLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return stubNoRootsLogClient{logURL: log.URL}, nil
}

func TestProxyRefreshRootsErr(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList, err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	p := NewProxy(llr, GetDistributorBuilder(ChromeCTPolicy, buildStubNoRootsLogClient))
	p.RefreshLogList(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// number of active Logs within sampleLogList
	var numLogs = 3
	for i := 0; i < numLogs; i++ {
		select {
		case <-p.Errors:
		case <-ctx.Done():
			t.Errorf("p.RefreshLogList() on noRootsDistributorFactory expected to emit error for each Log, got %d", i)
			return
		}
	}
}

func TestCTPolicyTypeFromString(t *testing.T) {
	testCases := []struct {
		name      string
		from      string
		wantPlc   CTPolicyType
		errRegexp *regexp.Regexp
	}{
		{
			name:      "chrome",
			from:      "chrome",
			wantPlc:   ChromeCTPolicy,
			errRegexp: nil,
		},
		{
			name:      "apple",
			from:      "apple",
			wantPlc:   AppleCTPolicy,
			errRegexp: nil,
		},
		{
			name:      "noValue",
			from:      "crome",
			wantPlc:   ChromeCTPolicy,
			errRegexp: regexp.MustCompile("CTPolicyTypeFromString does not support value"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotPlc, err := CTPolicyTypeFromString(tc.from)
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				var unwantedErr string
				if gotErr {
					unwantedErr = fmt.Sprintf(" (%q)", err)
				}
				t.Errorf("Got error = %v%s, expected error = %v", gotErr, unwantedErr, wantErr)
			} else if tc.errRegexp != nil && !tc.errRegexp.MatchString(err.Error()) {
				t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
			}
			if gotPlc != tc.wantPlc {
				t.Errorf("CtPolicyTypeFromStrin(%q) want %v, got %v", tc.from, tc.wantPlc, gotPlc)
			}
		})
	}
}
