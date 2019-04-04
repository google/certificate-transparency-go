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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	ct "github.com/google/certificate-transparency-go"
)

func buildStubLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return buildRootedStubLC(log, RootsCerts)
}

func ExampleDistributor() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := NewDistributor(sampleValidLogList(), buildStubCTPolicy(1), buildStubLogClient)
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

	scts, err := d.AddPreChain(ctx, pemFileToDERChain("../trillian/testdata/subleaf.chain"))
	if err != nil {
		panic(err)
	}
	for _, sct := range scts {
		fmt.Printf("%s\n", *sct)
	}
	// Output:
	// {ct.googleapis.com/rocketeer/ {Version:0 LogId:Y3QuZ29vZ2xlYXBpcy5jb20vcm9ja2V0ZWVyLwAAAAA= Timestamp:1234 Extensions:'' Signature:{{SHA256 ECDSA} []}}}
}

// readCertFile returns the first certificate it finds in file provided.
func readCertFile(filename string) []byte {
	data, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		return nil
	}
	return data[0]
}

var (
	RootsCerts = map[string][]rootInfo{
		"ct.googleapis.com/aviator/": {
			rootInfo{filename: "../trillian/testdata/fake-ca-1.cert"},
			rootInfo{filename: "testdata/some.cert"},
		},
		"ct.googleapis.com/rocketeer/": {
			rootInfo{filename: "../trillian/testdata/fake-ca.cert"},
			rootInfo{filename: "../trillian/testdata/fake-ca-1.cert"},
			rootInfo{filename: "testdata/some.cert"},
			rootInfo{filename: "testdata/another.cert"},
		},
		"ct.googleapis.com/icarus/": {
			rootInfo{raw: []byte("invalid000")},
			rootInfo{filename: "testdata/another.cert"},
		},
		"uncollectable-roots/log/": {
			rootInfo{raw: []byte("invalid")},
		},
	}
)

// buildNoLogClient is LogClientBuilder that always fails.
func buildNoLogClient(_ *loglist.Log) (client.AddLogClient, error) {
	return nil, errors.New("bad log-client builder")
}

// Stub for AddLogClient interface
type emptyLogClient struct {
}

func (e emptyLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (e emptyLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (e emptyLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	return nil, nil
}

// buildEmptyLogClient produces empty stub Log clients.
func buildEmptyLogClient(_ *loglist.Log) (client.AddLogClient, error) {
	return emptyLogClient{}, nil
}

func sampleLogList() *loglist.LogList {
	var loglist loglist.LogList
	if err := json.Unmarshal([]byte(testdata.SampleLogList), &loglist); err != nil {
		panic(fmt.Errorf("unable to Unmarshal testdata.SampleLogList: %v", err))
	}
	return &loglist
}

func sampleValidLogList() *loglist.LogList {
	ll := sampleLogList()
	// Id of invalid Log description Racketeer
	inval := 3
	ll.Logs = append(ll.Logs[:inval], ll.Logs[inval+1:]...)
	return ll
}

func sampleUncollectableLogList() *loglist.LogList {
	ll := sampleValidLogList()
	// Append loglist that is unable to provide roots on request.
	ll.Logs = append(ll.Logs, loglist.Log{
		Description: "Does not return roots", Key: []byte("VW5jb2xsZWN0YWJsZUxvZ0xpc3Q="),
		MaximumMergeDelay: 123, OperatedBy: []int{0},
		URL:            "uncollectable-roots/log/",
		DNSAPIEndpoint: "uncollectavle.ct.googleapis.com",
	})
	return ll
}

func TestNewDistributorLogClients(t *testing.T) {
	testCases := []struct {
		name      string
		ll        *loglist.LogList
		lcBuilder LogClientBuilder
		errRegexp *regexp.Regexp
	}{
		{
			name:      "ValidLogClients",
			ll:        sampleValidLogList(),
			lcBuilder: buildEmptyLogClient,
		},
		{
			name:      "NoLogClients",
			ll:        sampleValidLogList(),
			lcBuilder: buildNoLogClient,
			errRegexp: regexp.MustCompile("failed to create log client"),
		},
		{
			name:      "NoLogClientsEmptyLogList",
			ll:        &loglist.LogList{},
			lcBuilder: buildNoLogClient,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, tc.lcBuilder)
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

// TestSCT builds a mock SCT for given logURL.
func testSCT(logURL string) *ct.SignedCertificateTimestamp {
	var keyID [sha256.Size]byte
	copy(keyID[:], logURL)
	return &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: keyID},
		Timestamp:  1234,
		Extensions: []byte{},
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
		},
	}
}

func TestNewDistributorRootPools(t *testing.T) {
	testCases := []struct {
		name     string
		ll       *loglist.LogList
		rootNum  map[string]int
		wantErrs int
	}{
		{
			name: "InactiveZeroRoots",
			ll:   sampleValidLogList(),
			// aviator is not active; 1 of 2 icarus roots is not x509 struct
			rootNum:  map[string]int{"ct.googleapis.com/aviator/": 0, "ct.googleapis.com/rocketeer/": 4, "ct.googleapis.com/icarus/": 1},
			wantErrs: 1,
		},
		{
			name: "CouldNotCollect",
			ll:   sampleUncollectableLogList(),
			// aviator is not active; uncollectable client cannot provide roots
			rootNum:  map[string]int{"ct.googleapis.com/aviator/": 0, "ct.googleapis.com/rocketeer/": 4, "ct.googleapis.com/icarus/": 1, "uncollectable-roots/log/": 0},
			wantErrs: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dist, _ := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, buildStubLogClient)

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

func (stubP stubCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist.LogList) (ctpolicy.LogPolicyData, error) {
	baseGroup, err := ctpolicy.BaseGroupFor(approved, stubP.baseNum)
	groups := ctpolicy.LogPolicyData{baseGroup.Name: &baseGroup}
	return groups, err
}

func TestDistributorAddPreChain(t *testing.T) {
	testCases := []struct {
		name     string
		ll       *loglist.LogList
		plc      ctpolicy.CTPolicy
		rawChain [][]byte
		getRoots bool
		scts     []*AssignedSCT
		wantErr  bool
	}{
		{
			name:     "MalformedChainRequest with log roots available",
			ll:       sampleValidLogList(),
			plc:      ctpolicy.ChromeCTPolicy{},
			rawChain: pemFileToDERChain("../trillian/testdata/subleaf.misordered.chain"),
			getRoots: true,
			scts:     nil,
			wantErr:  true,
		},
		{
			name:     "MalformedChainRequest without log roots available",
			ll:       sampleValidLogList(),
			plc:      ctpolicy.ChromeCTPolicy{},
			rawChain: pemFileToDERChain("../trillian/testdata/subleaf.misordered.chain"),
			getRoots: false,
			scts:     nil,
			wantErr:  true,
		},
		{
			name:     "CallBeforeInit",
			ll:       sampleValidLogList(),
			plc:      ctpolicy.ChromeCTPolicy{},
			rawChain: nil,
			scts:     nil,
			wantErr:  true,
		},
		{
			name:     "InsufficientSCTsForPolicy",
			ll:       sampleValidLogList(),
			plc:      ctpolicy.AppleCTPolicy{},
			rawChain: pemFileToDERChain("../trillian/testdata/subleaf.chain"), // subleaf chain is fake-ca-1-rooted
			getRoots: true,
			scts:     []*AssignedSCT{},
			wantErr:  true, // Not enough SCTs for policy
		},
		{
			name:     "FullChain1Policy",
			ll:       sampleValidLogList(),
			plc:      buildStubCTPolicy(1),
			rawChain: pemFileToDERChain("../trillian/testdata/subleaf.chain"),
			getRoots: true,
			scts: []*AssignedSCT{
				{
					LogURL: "ct.googleapis.com/rocketeer/",
					SCT:    testSCT("ct.googleapis.com/rocketeer/"),
				},
			},
			wantErr: false,
		},
		// TODO(merkulova): Add tests to cover more cases where log roots aren't available
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, tc.plc, buildStubLogClient)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if tc.getRoots {
				if errs := dist.RefreshRoots(ctx); len(errs) != 1 || errs["ct.googleapis.com/icarus/"] == nil {
					// 1 error is expected, because the Icarus log has an invalid root (see RootCerts).
					t.Fatalf("dist.RefreshRoots() = %v, want 1 error for 'ct.googleapis.com/icarus/'", errs)
				}
			}

			scts, err := dist.AddPreChain(context.Background(), tc.rawChain)
			if gotErr := (err != nil); gotErr != tc.wantErr {
				t.Fatalf("dist.AddPreChain(%q) = (_, %v), want err? %t", tc.rawChain, err, tc.wantErr)
			} else if gotErr {
				return
			}

			if got, want := len(scts), len(tc.scts); got != want {
				t.Errorf("dist.AddPreChain(%q) = %d SCTs, want %d SCTs", tc.rawChain, got, want)
			}
			if diff := cmp.Diff(scts, tc.scts, cmpopts.SortSlices(func(x, y *AssignedSCT) bool {
				return x.LogURL < y.LogURL
			})); diff != "" {
				t.Errorf("dist.AddPreChain(%q): diff -want +got\n%s", tc.rawChain, diff)
			}
		})
	}
}
