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
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/testdata"
)

var (
	RootsCert = map[string][]string{
		"ct.googleapis.com/aviator/": {
			"MIIFLjCCAxagAwIBAgIQNgEiBHAkH6lLUWKp42Ob1DANBgkqhkiG9w0BAQ0FADAWMRQwEgYDVQQDEwtlc2lnbml0Lm9yZzAeFw0xNDA2MjAxODM3NTRaFw0zMDA2MjAxODQ3NDZaMBYxFDASBgNVBAMTC2VzaWduaXQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtylZx/zTLxRDsok14XO0Z3PvWMIY4HWro0YLgCF8dYv3tUaNkmN3ghlQvY8UcByH2LMOBGiQAcMHxgEJ53cnWRyc2DjoGhkDkiPdS2JttNEB0B/XTaGvaHwJh2CSgIBbpZpWTaqGywbe7AgJQ81L8h7tZ4E6W8ZM0vt4mnzqkPBT+BmyjTXG/McGhYTQAsmdsYZDBAdB2Y4X1/RAyL0e9MHdSboRofhg+8d5MeC0VEIgHXU/R4f4wz/pSw0FI9xxWJR3UUK/qOWqNsVYZfmCu6+ksDQtezxSTAuymoL094Dwn+hnXb8RS6dEbIQ+b0bIHxxpypcxH7rBMIpQcbZ8JSqNVDZPI9QahKNPQMQiuBE66KlqbnLOj7lGBxsbpU2Dx8QL8W96op6dTGtniFyXqhuYN2UxDMNI+fb1j9G7ENpoqvTVfjxa4RUU6uZ9ZygOiiOZD4P54vEQFteiu4OM+mWOm5Vll9yPXqHPc5oiCfyvCNVzfapqPoGbaCM6oQtcHdAca9VpE2eDTo36zfdFo31YYBOEjWNsfXwp8frNduS/L6gmWYrd91HeEoOVX2ZQKqBLp5ydW72xDSeCIr5kugqdY6whW80ugjLlc9mDd8/LEGQQKnrxzeeWdjiQG/WwcOse9GRktOzH2gvmkJ+vY82z1jhrZP4REoA6T+aYGR8CAwEAAaN4MHYwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPOGsFKraD+/FoPAUXSf77qYfZHRMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFEq/BT//OC3eNeJ4wEfNqJXdZRNpMA0GCSqGSIb3DQEBDQUAA4ICAQBEvh2kzI+1uoUx/emM654QvpM6WtgQSJMubKwKeBY5UNgwwNpwmtswiEKzdZwBiGb1xEehPrAKz0d7aiIIEOonYEohIV6szl0+F56nN16813n1lPsCjdLSA8fjgf28jvlTKcrLRqeyCn4APadh6g7/FRiGcmIxEFPf/VNTUBZ7l4e2zzb06PxCq8oDaOsbAVYXQz8A0KX50KURZrdC2knUg1HX0J/orVpdaQ9UZYVNp2WAbe9vYTCCF5FdtzNU+nJDojpDxF5guMe9bifL3YTvd87YQwsH7+o+UbtHX4lG8VsSfmvvJulNBY6RtzZEpZvyRWIvQahM9qTrzFpsxl4wyPSBDPLDZ6YvVWsXvU4PqLOWTbPdq4BB24P9kFxeYjEe/rDQ8bd1/V/OFZTEM0rxdZDDN9vWnybzl8xL5VmNLDGl1u6JrOVvCzVAWP++L9l5UTusQI/BPSMebz6msd8vhTluD4jQIba1/6zOwfBraFgCIktCT3GEIiyt59x3rdSirLyjzmeQA9NkwoG/GqlFlSdWmQCK/sCL+z050rqjL0kEwIl/D6ncCXfBvhCpCmcrIlZFruyeOlsISZ410T1w/pLK8OXhbCr13Gb7A5jhv1nn811cQaR7XUXhcn6Wq/VV/oQZLunBYvoYOs3dc8wpBabPrrRhkdNmN6Rib6TvMg==",
		},
		"ct.googleapis.com/rocketeer/": {
			"MIIFLjCCAxagAwIBAgIQNgEiBHAkH6lLUWKp42Ob1DANBgkqhkiG9w0BAQ0FADAWMRQwEgYDVQQDEwtlc2lnbml0Lm9yZzAeFw0xNDA2MjAxODM3NTRaFw0zMDA2MjAxODQ3NDZaMBYxFDASBgNVBAMTC2VzaWduaXQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtylZx/zTLxRDsok14XO0Z3PvWMIY4HWro0YLgCF8dYv3tUaNkmN3ghlQvY8UcByH2LMOBGiQAcMHxgEJ53cnWRyc2DjoGhkDkiPdS2JttNEB0B/XTaGvaHwJh2CSgIBbpZpWTaqGywbe7AgJQ81L8h7tZ4E6W8ZM0vt4mnzqkPBT+BmyjTXG/McGhYTQAsmdsYZDBAdB2Y4X1/RAyL0e9MHdSboRofhg+8d5MeC0VEIgHXU/R4f4wz/pSw0FI9xxWJR3UUK/qOWqNsVYZfmCu6+ksDQtezxSTAuymoL094Dwn+hnXb8RS6dEbIQ+b0bIHxxpypcxH7rBMIpQcbZ8JSqNVDZPI9QahKNPQMQiuBE66KlqbnLOj7lGBxsbpU2Dx8QL8W96op6dTGtniFyXqhuYN2UxDMNI+fb1j9G7ENpoqvTVfjxa4RUU6uZ9ZygOiiOZD4P54vEQFteiu4OM+mWOm5Vll9yPXqHPc5oiCfyvCNVzfapqPoGbaCM6oQtcHdAca9VpE2eDTo36zfdFo31YYBOEjWNsfXwp8frNduS/L6gmWYrd91HeEoOVX2ZQKqBLp5ydW72xDSeCIr5kugqdY6whW80ugjLlc9mDd8/LEGQQKnrxzeeWdjiQG/WwcOse9GRktOzH2gvmkJ+vY82z1jhrZP4REoA6T+aYGR8CAwEAAaN4MHYwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFPOGsFKraD+/FoPAUXSf77qYfZHRMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFEq/BT//OC3eNeJ4wEfNqJXdZRNpMA0GCSqGSIb3DQEBDQUAA4ICAQBEvh2kzI+1uoUx/emM654QvpM6WtgQSJMubKwKeBY5UNgwwNpwmtswiEKzdZwBiGb1xEehPrAKz0d7aiIIEOonYEohIV6szl0+F56nN16813n1lPsCjdLSA8fjgf28jvlTKcrLRqeyCn4APadh6g7/FRiGcmIxEFPf/VNTUBZ7l4e2zzb06PxCq8oDaOsbAVYXQz8A0KX50KURZrdC2knUg1HX0J/orVpdaQ9UZYVNp2WAbe9vYTCCF5FdtzNU+nJDojpDxF5guMe9bifL3YTvd87YQwsH7+o+UbtHX4lG8VsSfmvvJulNBY6RtzZEpZvyRWIvQahM9qTrzFpsxl4wyPSBDPLDZ6YvVWsXvU4PqLOWTbPdq4BB24P9kFxeYjEe/rDQ8bd1/V/OFZTEM0rxdZDDN9vWnybzl8xL5VmNLDGl1u6JrOVvCzVAWP++L9l5UTusQI/BPSMebz6msd8vhTluD4jQIba1/6zOwfBraFgCIktCT3GEIiyt59x3rdSirLyjzmeQA9NkwoG/GqlFlSdWmQCK/sCL+z050rqjL0kEwIl/D6ncCXfBvhCpCmcrIlZFruyeOlsISZ410T1w/pLK8OXhbCr13Gb7A5jhv1nn811cQaR7XUXhcn6Wq/VV/oQZLunBYvoYOs3dc8wpBabPrrRhkdNmN6Rib6TvMg==",
		},
		"ct.googleapis.com/icarus/": {
			"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ",
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
	loglist := sampleLogList(t)
	// Id of invalid Log description Racketeer
	inval := 3
	loglist.Logs = append(loglist.Logs[:inval], loglist.Logs[inval+1:]...)
	return loglist
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
				t.Errorf("Got error = %v, expected error = %v", (err == nil), (tc.errRegexp == nil))
			} else if tc.errRegexp != nil && !tc.errRegexp.MatchString(err.Error()) {
				t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
			}
		})
	}
}

// Mock for AddLogCLient interface
type mockLogClient struct {
	logURL string
}

func (m mockLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (m mockLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (m mockLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	roots := []ct.ASN1Cert{}
	if certs, ok := RootsCert[m.logURL]; ok {
		for _, cert64 := range certs {
			cert, err := base64.StdEncoding.DecodeString(cert64)
			if err != nil {
				return nil, err
			}
			roots = append(roots, ct.ASN1Cert{Data: cert})
		}
	}
	return roots, nil
}

// buildNoLogClient is LogClientBuilder that always fails.
func buildMockLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return mockLogClient{logURL: log.URL}, nil
}

func TestNewDistributorRootPools(t *testing.T) {
	testCases := []struct {
		name    string
		ll      *loglist.LogList
		rootNum map[string]int
	}{
		{
			name:    "MockRoots",
			ll:      sampleValidLogList(t),
			rootNum: map[string]int{"ct.googleapis.com/aviator/": 0, "ct.googleapis.com/rocketeer/": 1, "ct.googleapis.com/icarus/": 1}, // aviator is not active
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dist, _ := NewDistributor(tc.ll, ctpolicy.ChromeCTPolicy{}, buildMockLogClient)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			dist.Run(ctx)
			for logURL, expectedNum := range tc.rootNum {
				gotNum := 0
				if roots, ok := dist.logRoots[logURL]; ok {
					gotNum = len(roots)
				}
				if expectedNum != gotNum {
					t.Errorf("Expected %d root(s) for Log %s, got %d", expectedNum, logURL, gotNum)
				}
			}
		})
	}
}
