// Copyright 2026 Google LLC. All Rights Reserved.
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

package x509util_test

import (
	"strings"
	"testing"

	"github.com/google/certificate-transparency-go/x509util"
)

// pemRPKIAddressRangeCert is a self-signed certificate whose RFC 3779
// sbgp-ipAddrBlock extension holds:
//
//	IPv4: 10.0.0.0-10.0.2.255, 10.5.0.0-10.5.11.255, 192.168.0.0/16
//	IPv6: 2001:db8::-2001:db8:0:2:ffff:ffff:ffff:ffff
const pemRPKIAddressRangeCert = `
-----BEGIN CERTIFICATE-----
MIIBrzCCAVSgAwIBAgIUbm8z8LlBpOz58dJYrQFGk6LC3l4wCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXUlBLSSBhZGRyZXNzIHJhbmdlIHRlc3QwHhcNMjYxMTE0MTQw
NjI2WhcNMzYxMTExMTQwNjI2WjAiMSAwHgYDVQQDDBdSUEtJIGFkZHJlc3MgcmFu
Z2UgdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDHzct8ORrDQmNS4lXsK
WTMq0eHxq8Mbh9T7ydvW2eLZArDHUpHClyebLA4Dy34pWkJGMqjLB2NOxDgA9tmE
jV+jaDBmMA8GA1UdEwEB/wQFMAMBAf8wUwYIKwYBBQUHAQcBAf8ERDBCMCQEAgAB
MB4wCgMCAQoDBAAKAAIwCwMDAAoFAwQCCgUIAwMAwKgwGgQCAAIwFDASAwUDIAEN
uAMJACABDbgAAAACMAoGCCqGSM49BAMCA0kAMEYCIQC74fznw/A8uFKXQdM+A0rE
DM1E78oQ/qVtxXuJldKEVgIhAI4eQS85iUJAdfMkpzvvzJSxDxfYJn2cSVnfJsF4
yqSb
-----END CERTIFICATE-----`

func TestCertificateToStringRPKIAddressRanges(t *testing.T) {
	cert, err := x509util.CertificateFromPEM([]byte(strings.TrimSpace(pemRPKIAddressRangeCert)))
	if err != nil {
		t.Fatalf("CertificateFromPEM()=_,%v; want _,nil", err)
	}
	got := x509util.CertificateToString(cert)
	for _, want := range []string{
		"\n                  [10.0.0.0, 10.0.2.255]\n",
		"\n                  [10.5.0.0, 10.5.11.255]\n",
		"\n                  192.168.0.0/16\n",
		"\n                  [2001:db8::, 2001:db8:0:2:ffff:ffff:ffff:ffff]\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CertificateToString() output does not contain %q", want)
		}
	}
	if t.Failed() {
		t.Logf("CertificateToString() output:\n%s", got)
	}
}
