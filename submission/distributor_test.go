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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"

	"github.com/google/go-cmp/cmp"
)

// ReadCertFile returns the first certificate it finds in file provided.
func readCertFile(filename string) string {
	fmt.Println(filename)
	data, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		return ""
	}
	return string(data[0])
}

var (
	RootsCerts = map[string][]string{
		"ct.googleapis.com/aviator/": {
			readCertFile("../trillian/testdata/fake-ca-1.cert"),
			readCertFile("testdata/some.cert"),
		},
		"ct.googleapis.com/rocketeer/": {
			readCertFile("../trillian/testdata/fake-ca.cert"),
			readCertFile("../trillian/testdata/fake-ca-1.cert"),
			readCertFile("testdata/some.cert"),
			readCertFile("testdata/another.cert"),
		},
		"ct.googleapis.com/icarus/": {
			"aW52YWxpZDAwMA==", // encoded 'invalid000'
			readCertFile("testdata/another.cert"),
		},
		"uncollectable-roots/log/": {
			"invalid",
		},
	}
)

// buildNoLogClient is LogClientBuilder that always fails.
func buildNoLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return nil, errors.New("bad client builder")
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
func buildEmptyLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return emptyLogClient{}, nil
}

func sampleLogList(t *testing.T) *loglist.LogList {
	t.Helper()
	var loglist loglist.LogList
	err := json.Unmarshal([]byte(testdata.SampleLogList), &loglist)
	if err != nil {
		t.Fatalf("Unable to Unmarshal testdata.SampleLogList %v", err)
	}
	return &loglist
}

func sampleValidLogList(t *testing.T) *loglist.LogList {
	t.Helper()
	ll := sampleLogList(t)
	// Id of invalid Log description Racketeer
	inval := 3
	ll.Logs = append(ll.Logs[:inval], ll.Logs[inval+1:]...)
	return ll
}

func sampleUncollectableLogList(t *testing.T) *loglist.LogList {
	t.Helper()
	ll := sampleValidLogList(t)
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
			ll:        sampleValidLogList(t),
			lcBuilder: buildEmptyLogClient,
		},
		{
			name:      "NoLogClients",
			ll:        sampleValidLogList(t),
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

// Stub for AddLogCLient interface
type stubLogClient struct {
	logURL string
}

func (m stubLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (m stubLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	if _, ok := RootsCerts[m.logURL]; ok {
		return testSCT(m.logURL), nil
	}
	return nil, fmt.Errorf("Log %q has no roots", m.logURL)
}

func (m stubLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	roots := []ct.ASN1Cert{}
	if certs, ok := RootsCerts[m.logURL]; ok {
		for _, cert := range certs {
			roots = append(roots, ct.ASN1Cert{Data: []byte(cert)})
		}
	}
	return roots, nil
}

func buildStubLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return stubLogClient{logURL: log.URL}, nil
}

func TestNewDistributorRootPools(t *testing.T) {
	testCases := []struct {
		name    string
		ll      *loglist.LogList
		rootNum map[string]int
	}{
		{
			name:    "InactiveZeroRoots",
			ll:      sampleValidLogList(t),
			rootNum: map[string]int{"ct.googleapis.com/aviator/": 0, "ct.googleapis.com/rocketeer/": 4, "ct.googleapis.com/icarus/": 1}, // aviator is not active; 1 of 2 icarus roots is not x509 struct
		},
		{
			name:    "CouldNotCollect",
			ll:      sampleUncollectableLogList(t),
			rootNum: map[string]int{"ct.googleapis.com/aviator/": 0, "ct.googleapis.com/rocketeer/": 4, "ct.googleapis.com/icarus/": 1, "uncollectable-roots/log/": 0}, // aviator is not active; uncollectable client cannot provide roots
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, buildStubLogClient)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			go dist.Run(ctx)
			// First Log refresh expected.
			<-ctx.Done()

			dist.mu.Lock()
			defer dist.mu.Unlock()
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

func pemFileToDERChain(t *testing.T, filename string) [][]byte {
	t.Helper()
	rawChain, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		t.Fatalf("failed to load testdata: %v", err)
	}
	return rawChain
}

func getSCTMap(l []*AssignedSCT) map[string]*AssignedSCT {
	m := map[string]*AssignedSCT{}
	for _, asct := range l {
		m[asct.LogURL] = asct
	}
	return m
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
		scts     []*AssignedSCT
		wantErr  bool
	}{
		{
			name:     "MalformedChainRequest",
			ll:       sampleValidLogList(t),
			plc:      ctpolicy.ChromeCTPolicy{},
			rawChain: pemFileToDERChain(t, "../trillian/testdata/subleaf.misordered.chain"),
			scts:     nil,
			wantErr:  true,
		},
		{
			name:     "CallBeforeInit",
			ll:       sampleValidLogList(t),
			plc:      ctpolicy.ChromeCTPolicy{},
			rawChain: nil,
			scts:     nil,
			wantErr:  true,
		},
		{
			name:     "InsufficientSCTsForPolicy",
			ll:       sampleValidLogList(t),
			plc:      ctpolicy.AppleCTPolicy{},
			rawChain: pemFileToDERChain(t, "../trillian/testdata/subleaf.chain"), // subleaf chain is fake-ca-1-rooted
			scts:     []*AssignedSCT{},
			wantErr:  true, // Not enough SCTs for policy
		},
		{
			name:     "FullChain1Policy",
			ll:       sampleValidLogList(t),
			plc:      buildStubCTPolicy(1),
			rawChain: pemFileToDERChain(t, "../trillian/testdata/subleaf.chain"),
			scts: []*AssignedSCT{
				{
					LogURL: "ct.googleapis.com/rocketeer/",
					SCT:    testSCT("ct.googleapis.com/rocketeer/"),
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, tc.plc, buildStubLogClient)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			dist.Run(ctx)

			scts, err := dist.AddPreChain(context.Background(), tc.rawChain)
			if gotErr := (err != nil); gotErr != tc.wantErr {
				t.Errorf("Expected to get errors is %v while actually getting errors is %v", tc.wantErr, gotErr)
			}

			if got, want := len(scts), len(tc.scts); got != want {
				t.Errorf("Expected to get %d SCTs on AddPreChain request, got %d", want, got)
			}
			gotMap := getSCTMap(tc.scts)
			for _, asct := range scts {
				if wantedSCT, ok := gotMap[asct.LogURL]; !ok {
					t.Errorf("dist.AddPreChain() = (_, %v), want err? %t", err, tc.wantErr)
				} else if diff := cmp.Diff(asct, wantedSCT); diff != "" {
					t.Errorf("Got unexpected SCT for Log %q", asct.LogURL)
				}
			}
		})
	}
}
