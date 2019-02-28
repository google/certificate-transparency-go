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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
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

	"io/ioutil"
)

// ReadPEMFile returns the first certificate it finds in pemFile, as base64-encoded DER
func readPEMFile(pemFile string) string {
	pemCerts, _ := ioutil.ReadFile(pemFile)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		return base64.StdEncoding.EncodeToString(block.Bytes)
	}
	return ""
}

var (
	RootsCerts = map[string][]string{
		"ct.googleapis.com/aviator/": {
			readPEMFile("../trillian/testdata/fake-ca-1.cert"),
			"MIIFLjCCAxagAwIBAgIQNgEiBHAkH6lLUWKp42Ob1DANBgkqhkiG9w0BAQ0FADAWMRQwEgYDVQQDEwtlc2lnbml0Lm9yZzAeFw0xNDA2MjAxODM3NTRaFw0zMDA2MjAxODQ3NDZaMBYxFDASBgNVBAMTC2VzaWduaXQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtylZx/zTLxRDsok14XO0Z3PvWMIY4HWro0YLgCF8dYv3tUaNkmN3ghlQvY8UcByH2LMOBGiQAcMHxgEJ53cnWRyc2DjoGhkDkiPdS2JttNEB0B/XTaGvaHwJh2CSgIBbpZpWTaqGywbe7AgJQ81L8h7tZ4E6W8ZM0vt4mnzqkPBT+BmyjTXG/McGhYTQAsmdsYZDBAdB2Y4X1/RAyL0e9MHdSboRofhg+8d5MeC0VEIgHXU/R4f4wz/pSw0FI9xxWJR3UUK/qOWqNsVYZfmCu6+ksDQtezxSTAuymoL094Dwn+hnXb8RS6dEbIQ+b0bIHxxpypcxH7rBMIpQcbZ8JSqNVDZPI9QahKNPQMQiuBE66KlqbnLOj7lGBxsbpU2Dx8QL8W96op6dTGtniFyXqhuYN2UxDMNI+fb1j9G7ENpoqvTVfjxa4RUU6uZ9ZygOiiOZD4P54vEQFteiu4OM+mWOm5Vll9yPXqHPc5oiCfyvCNVzfapqPoGbaCM6oQtcHdAca9VpE2eDTo36zfdFo31YYBOEjWNsfXwp8frNduS/L6gmWYrd91HeEoOVX2ZQKqBLp5ydW72xDSeCIr5kugqdY6whW80ugjLlc9mDd8/LEGQQKnrxzeeWdjiQG/WwcOse9GRktOzH2gvmkJ+vY82z1jhrZP4REoA6T+aYGR8CAwEAAaN4MHYwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPOGsFKraD+/FoPAUXSf77qYfZHRMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFEq/BT//OC3eNeJ4wEfNqJXdZRNpMA0GCSqGSIb3DQEBDQUAA4ICAQBEvh2kzI+1uoUx/emM654QvpM6WtgQSJMubKwKeBY5UNgwwNpwmtswiEKzdZwBiGb1xEehPrAKz0d7aiIIEOonYEohIV6szl0+F56nN16813n1lPsCjdLSA8fjgf28jvlTKcrLRqeyCn4APadh6g7/FRiGcmIxEFPf/VNTUBZ7l4e2zzb06PxCq8oDaOsbAVYXQz8A0KX50KURZrdC2knUg1HX0J/orVpdaQ9UZYVNp2WAbe9vYTCCF5FdtzNU+nJDojpDxF5guMe9bifL3YTvd87YQwsH7+o+UbtHX4lG8VsSfmvvJulNBY6RtzZEpZvyRWIvQahM9qTrzFpsxl4wyPSBDPLDZ6YvVWsXvU4PqLOWTbPdq4BB24P9kFxeYjEe/rDQ8bd1/V/OFZTEM0rxdZDDN9vWnybzl8xL5VmNLDGl1u6JrOVvCzVAWP++L9l5UTusQI/BPSMebz6msd8vhTluD4jQIba1/6zOwfBraFgCIktCT3GEIiyt59x3rdSirLyjzmeQA9NkwoG/GqlFlSdWmQCK/sCL+z050rqjL0kEwIl/D6ncCXfBvhCpCmcrIlZFruyeOlsISZ410T1w/pLK8OXhbCr13Gb7A5jhv1nn811cQaR7XUXhcn6Wq/VV/oQZLunBYvoYOs3dc8wpBabPrrRhkdNmN6Rib6TvMg==",
		},
		"ct.googleapis.com/rocketeer/": {
			readPEMFile("../trillian/testdata/fake-ca.cert"),
			readPEMFile("../trillian/testdata/fake-ca-1.cert"),
			"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",
		},
		"ct.googleapis.com/icarus/": {
			"aW52YWxpZDAwMA==", // encoded 'invalid000'
			"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ",
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
		for _, cert64 := range certs {
			cert, err := base64.StdEncoding.DecodeString(cert64)
			if err != nil {
				return nil, err
			}
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
			name:     "FullChainApplePolicy",
			ll:       sampleValidLogList(t),
			plc:      ctpolicy.AppleCTPolicy{},
			rawChain: pemFileToDERChain(t, "../trillian/testdata/subleaf.chain"), // subleaf chain is fake-ca-1-rooted
			scts: []*AssignedSCT{
				{
					LogURL: "ct.googleapis.com/rocketeer/",
					SCT:    testSCT("ct.googleapis.com/rocketeer/"),
				},
			},
			wantErr: true, // Not enough SCTs for policy
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

			go dist.Run(ctx)
			// First Log refresh expected.
			<-ctx.Done()

			scts, err := dist.AddPreChain(context.Background(), tc.rawChain)
			if gotErr := (err != nil); gotErr != tc.wantErr {
				t.Errorf("Expected to get errors is %v while actually getting errors is %v", tc.wantErr, gotErr)
			}

			var gotNum, wantNum int
			if scts != nil {
				gotNum = len(scts)
			}
			if tc.scts != nil {
				wantNum = len(tc.scts)
			}
			if gotNum != wantNum {
				t.Errorf("Expected to get %d SCTs on AddPreChain request, got %d", wantNum, gotNum)
			}
			gotMap := getSCTMap(tc.scts)
			for _, asct := range scts {
				if wantedSCT, ok := gotMap[asct.LogURL]; !ok {
					t.Errorf("Expected to get SCT from Log %q, but got none", asct.LogURL)
				} else if !reflect.DeepEqual(asct, wantedSCT) {
					t.Errorf("Got unexpected SCT for Log %q", asct.LogURL)
				}
			}
		})
	}
}
