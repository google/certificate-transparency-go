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
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/trillian/monitoring"
)

func newLocalStubLogClient(log *loglist2.Log) (client.AddLogClient, error) {
	return newRootedStubLogClient(log, RootsCerts)
}

func ExampleDistributor() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := NewDistributor(sampleValidLogList(), buildStubCTPolicy(1), newLocalStubLogClient, monitoring.InertMetricFactory{})
	if err != nil {
		panic(err)
	}

	// Refresh roots periodically so they stay up-to-date.
	// Not necessary for this example, but appropriate for long-running systems.
	refresh := make(chan struct{})
	go schedule.Every(ctx, time.Hour, func(ctx context.Context) {
		if errs := d.RefreshRoots(ctx); len(errs) > 0 {
			glog.Error(errs)
		}
		refresh <- struct{}{}
	})

	select {
	case <-refresh:
		break
	case <-ctx.Done():
		panic("Context expired")
	}

	scts, err := d.AddPreChain(ctx, pemFileToDERChain("../trillian/testdata/subleaf-pre.chain"), false /* loadPendingLogs */)
	if err != nil {
		panic(err)
	}
	for _, sct := range scts {
		fmt.Printf("%s\n", *sct)
	}
	// Output:
	// {https://ct.googleapis.com/rocketeer/ {Version:0 LogId:aHR0cHM6Ly9jdC5nb29nbGVhcGlzLmNvbS9yb2NrZXQ= Timestamp:1234 Extensions:'' Signature:{{SHA256 ECDSA} []}}}
}

var (
	RootsCerts = map[string][]rootInfo{
		"https://ct.googleapis.com/aviator/": {
			rootInfo{filename: "../trillian/testdata/fake-ca-1.cert"},
			rootInfo{filename: "testdata/some.cert"},
		},
		"https://ct.googleapis.com/rocketeer/": {
			rootInfo{filename: "../trillian/testdata/fake-ca.cert"},
			rootInfo{filename: "../trillian/testdata/fake-ca-1.cert"},
			rootInfo{filename: "testdata/some.cert"},
			rootInfo{filename: "testdata/another.cert"},
		},
		"https://ct.googleapis.com/icarus/": {
			rootInfo{raw: []byte("invalid000")},
			rootInfo{filename: "testdata/another.cert"},
		},
		"uncollectable-roots/log/": {
			rootInfo{raw: []byte("invalid")},
		},
	}
)

// newNoLogClient is LogClientBuilder that always fails.
func newNoLogClient(_ *loglist2.Log) (client.AddLogClient, error) {
	return nil, errors.New("bad log-client builder")
}

func sampleLogList() *loglist2.LogList {
	var ll loglist2.LogList
	if err := json.Unmarshal([]byte(testdata.SampleLogList2), &ll); err != nil {
		panic(fmt.Errorf("unable to Unmarshal testdata.SampleLogList: %v", err))
	}
	return &ll
}

func sampleValidLogList() *loglist2.LogList {
	ll := sampleLogList()
	// Id of invalid Log description Racketeer
	inval := 2
	ll.Operators[0].Logs = append(ll.Operators[0].Logs[:inval], ll.Operators[0].Logs[inval+1:]...)
	return ll
}

func sampleUncollectableLogList() *loglist2.LogList {
	ll := sampleValidLogList()
	// Append loglist that is unable to provide roots on request.
	ll.Operators[0].Logs = append(ll.Operators[0].Logs, &loglist2.Log{
		Description: "Does not return roots", Key: []byte("VW5jb2xsZWN0YWJsZUxvZ0xpc3Q="),
		URL:   "uncollectable-roots/log/",
		DNS:   "uncollectavle.ct.googleapis.com",
		MMD:   123,
		State: &loglist2.LogStates{Usable: &loglist2.LogState{}},
	})
	return ll
}

func TestNewDistributorLogClients(t *testing.T) {
	testCases := []struct {
		name      string
		ll        *loglist2.LogList
		lcBuilder LogClientBuilder
		errRegexp *regexp.Regexp
	}{
		{
			name:      "ValidLogClients",
			ll:        sampleValidLogList(),
			lcBuilder: newEmptyStubLogClient,
		},
		{
			name:      "NoLogClients",
			ll:        sampleValidLogList(),
			lcBuilder: newNoLogClient,
			errRegexp: regexp.MustCompile("failed to create log client"),
		},
		{
			name:      "NoLogClientsEmptyLogList",
			ll:        &loglist2.LogList{},
			lcBuilder: newNoLogClient,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, tc.lcBuilder, monitoring.InertMetricFactory{})
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				var unwantedErr string
				if gotErr {
					unwantedErr = fmt.Sprintf(" (%q)", err)
				}
				t.Errorf("Got error = %v%s, expected error = %v", gotErr, unwantedErr, wantErr)
			} else if tc.errRegexp != nil && !tc.errRegexp.MatchString(err.Error()) {
				t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
			}
		})
	}
}

func TestNewDistributorRootPools(t *testing.T) {
	testCases := []struct {
		name     string
		ll       *loglist2.LogList
		rootNum  map[string]int
		wantErrs int
	}{
		{
			name: "InactiveZeroRoots",
			ll:   sampleValidLogList(),
			// aviator is not active; 1 of 2 icarus roots is not x509 struct
			rootNum:  map[string]int{"https://ct.googleapis.com/aviator/": 0, "https://ct.googleapis.com/rocketeer/": 4, "https://ct.googleapis.com/icarus/": 1},
			wantErrs: 1,
		},
		{
			name: "CouldNotCollect",
			ll:   sampleUncollectableLogList(),
			// aviator is not active; uncollectable client cannot provide roots
			rootNum:  map[string]int{"https://ct.googleapis.com/aviator/": 0, "https://ct.googleapis.com/rocketeer/": 4, "https://ct.googleapis.com/icarus/": 1, "uncollectable-roots/log/": 0},
			wantErrs: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dist, _ := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, newLocalStubLogClient, monitoring.InertMetricFactory{})

			if errs := dist.RefreshRoots(ctx); len(errs) != tc.wantErrs {
				t.Errorf("dist.RefreshRoots() = %v, want %d errors", errs, tc.wantErrs)
			}

			for logURL, wantNum := range tc.rootNum {
				gotNum := 0
				if roots, ok := dist.logRoots[logURL]; ok {
					gotNum = len(roots.RawCertificates())
				}
				if wantNum != gotNum {
					t.Errorf("Expected %d root(s) for Log %s, got %d", wantNum, logURL, gotNum)
				}
			}
		})
	}
}

func pemFileToDERChain(filename string) [][]byte {
	if len(filename) == 0 {
		return nil
	}
	rawChain, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		panic(err)
	}
	return rawChain
}

// Stub CT policy to run tests.
type stubCTPolicy struct {
	baseNum int
}

// Builds simplistic policy requiring n SCTs from any Logs for each cert.
func buildStubCTPolicy(n int) stubCTPolicy {
	return stubCTPolicy{baseNum: n}
}

func (stubP stubCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist2.LogList) (ctpolicy.LogPolicyData, error) {
	baseGroup, err := ctpolicy.BaseGroupFor(approved, stubP.baseNum)
	groups := ctpolicy.LogPolicyData{baseGroup.Name: baseGroup}
	return groups, err
}

func (stubP stubCTPolicy) Name() string {
	return "stub"
}

func TestDistributorAddChain(t *testing.T) {
	testCases := []struct {
		name         string
		ll           *loglist2.LogList
		plc          ctpolicy.CTPolicy
		pemChainFile string
		getRoots     bool
		scts         []*AssignedSCT
		wantErr      bool
	}{
		{
			name:         "MalformedChainRequest with log roots available",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf.misordered.chain",
			getRoots:     true,
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "MalformedChainRequest without log roots available",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf.misordered.chain",
			getRoots:     false,
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "CallBeforeInit",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "",
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "InsufficientSCTsForPolicy",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.AppleCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf.chain", // subleaf chain is fake-ca-1-rooted
			getRoots:     true,
			scts:         []*AssignedSCT{},
			wantErr:      true, // Not enough SCTs for policy
		},
		{
			name:         "FullChain1Policy",
			ll:           sampleValidLogList(),
			plc:          buildStubCTPolicy(1),
			pemChainFile: "../trillian/testdata/subleaf.chain",
			getRoots:     true,
			scts: []*AssignedSCT{
				{
					LogURL: "https://ct.googleapis.com/rocketeer/",
					SCT:    testSCT("https://ct.googleapis.com/rocketeer/"),
				},
			},
			wantErr: false,
		},
		// TODO(merkulova): Add tests to cover more cases where log roots aren't available
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, tc.plc, newLocalStubLogClient, monitoring.InertMetricFactory{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if tc.getRoots {
				if errs := dist.RefreshRoots(ctx); len(errs) != 1 || errs["https://ct.googleapis.com/icarus/"] == nil {
					// 1 error is expected, because the Icarus log has an invalid root (see RootCerts).
					t.Fatalf("dist.RefreshRoots() = %v, want 1 error for 'https://ct.googleapis.com/icarus/'", errs)
				}
			}

			scts, err := dist.AddChain(context.Background(), pemFileToDERChain(tc.pemChainFile), false /* loadPendingLogs */)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("dist.AddChain(from %q) = (_, error: %v), want err? %t", tc.pemChainFile, err, tc.wantErr)
			} else if gotErr {
				return
			}

			if got, want := len(scts), len(tc.scts); got != want {
				t.Errorf("dist.AddChain(from %q) = %d SCTs, want %d SCTs", tc.pemChainFile, got, want)
			}
			if diff := cmp.Diff(scts, tc.scts, cmpopts.SortSlices(func(x, y *AssignedSCT) bool {
				return x.LogURL < y.LogURL
			})); diff != "" {
				t.Errorf("dist.AddChain(from %q): diff -want +got\n%s", tc.pemChainFile, diff)
			}
		})
	}
}

// TestDistributorAddChain copy but for pre-chain calls.
func TestDistributorAddPreChain(t *testing.T) {
	testCases := []struct {
		name         string
		ll           *loglist2.LogList
		plc          ctpolicy.CTPolicy
		pemChainFile string
		getRoots     bool
		scts         []*AssignedSCT
		wantErr      bool
	}{
		{
			name:         "MalformedChainRequest with log roots available",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf-pre.misordered.chain",
			getRoots:     true,
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "MalformedChainRequest without log roots available",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf-pre.misordered.chain",
			getRoots:     false,
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "CallBeforeInit",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.ChromeCTPolicy{},
			pemChainFile: "",
			scts:         nil,
			wantErr:      true,
		},
		{
			name:         "InsufficientSCTsForPolicy",
			ll:           sampleValidLogList(),
			plc:          ctpolicy.AppleCTPolicy{},
			pemChainFile: "../trillian/testdata/subleaf-pre.chain", // subleaf chain is fake-ca-1-rooted
			getRoots:     true,
			scts:         []*AssignedSCT{},
			wantErr:      true, // Not enough SCTs for policy
		},
		{
			name:         "FullChain1Policy",
			ll:           sampleValidLogList(),
			plc:          buildStubCTPolicy(1),
			pemChainFile: "../trillian/testdata/subleaf-pre.chain",
			getRoots:     true,
			scts: []*AssignedSCT{
				{
					LogURL: "https://ct.googleapis.com/rocketeer/",
					SCT:    testSCT("https://ct.googleapis.com/rocketeer/"),
				},
			},
			wantErr: false,
		},
		// TODO(merkulova): Add tests to cover more cases where log roots aren't available
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, tc.plc, newLocalStubLogClient, monitoring.InertMetricFactory{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if tc.getRoots {
				if errs := dist.RefreshRoots(ctx); len(errs) != 1 || errs["https://ct.googleapis.com/icarus/"] == nil {
					// 1 error is expected, because the Icarus log has an invalid root (see RootCerts).
					t.Fatalf("dist.RefreshRoots() = %v, want 1 error for 'https://ct.googleapis.com/icarus/'", errs)
				}
			}

			scts, err := dist.AddPreChain(context.Background(), pemFileToDERChain(tc.pemChainFile), true /* loadPendingLogs */)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("dist.AddPreChain(from %q) = (_, error: %v), want err? %t", tc.pemChainFile, err, tc.wantErr)
			} else if gotErr {
				return
			}

			if got, want := len(scts), len(tc.scts); got != want {
				t.Errorf("dist.AddPreChain(from %q) = %d SCTs, want %d SCTs", tc.pemChainFile, got, want)
			}
			if diff := cmp.Diff(scts, tc.scts, cmpopts.SortSlices(func(x, y *AssignedSCT) bool {
				return x.LogURL < y.LogURL
			})); diff != "" {
				t.Errorf("dist.AddPreChain(from %q): diff -want +got\n%s", tc.pemChainFile, diff)
			}
		})
	}
}

func TestDistributorAddTypeMismatch(t *testing.T) {
	testCases := []struct {
		name         string
		asPreChain   bool
		pemChainFile string
		scts         []*AssignedSCT
		wantErr      bool
	}{
		{
			name:         "FullChain1PolicyCertToPreAdd",
			asPreChain:   true,
			pemChainFile: "../trillian/testdata/subleaf.chain",
			scts:         nil,
			wantErr:      true, // Sending valid cert via AddPreChain call
		},
		{
			name:         "FullChain1PolicyPreCertToAdd",
			asPreChain:   false,
			pemChainFile: "../trillian/testdata/subleaf-pre.chain",
			scts:         nil,
			wantErr:      true, // Sending pre-cert via AddChain call
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(sampleValidLogList(), buildStubCTPolicy(1), newLocalStubLogClient, monitoring.InertMetricFactory{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if errs := dist.RefreshRoots(ctx); len(errs) != 1 || errs["https://ct.googleapis.com/icarus/"] == nil {
				// 1 error is expected, because the Icarus log has an invalid root (see RootCerts).
				t.Fatalf("dist.RefreshRoots() = %v, want 1 error for 'https://ct.googleapis.com/icarus/'", errs)
			}

			var scts []*AssignedSCT
			var err error
			if tc.asPreChain {
				scts, err = dist.AddPreChain(context.Background(), pemFileToDERChain(tc.pemChainFile), false /* loadPendingLogs */)
			} else {
				scts, err = dist.AddChain(context.Background(), pemFileToDERChain(tc.pemChainFile), false /* loadPendingLogs */)
			}

			pre := ""
			if tc.asPreChain {
				pre = "Pre"
			}
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("dist.Add%sChain(from %q) = (_, error: %v), want err? %t", pre, tc.pemChainFile, err, tc.wantErr)
			} else if gotErr {
				return
			}

			if got, want := len(scts), len(tc.scts); got != want {
				t.Errorf("dist.Add%sChain(from %q) = %d SCTs, want %d SCTs", pre, tc.pemChainFile, got, want)
			}
			if diff := cmp.Diff(scts, tc.scts, cmpopts.SortSlices(func(x, y *AssignedSCT) bool {
				return x.LogURL < y.LogURL
			})); diff != "" {
				t.Errorf("dist.Add%sChain(from %q): diff -want +got\n%s", pre, tc.pemChainFile, diff)
			}
		})
	}
}
