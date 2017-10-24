// Copyright 2016 Google Inc. All Rights Reserved.
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

package ctfe

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func wipeExtensions(cert *x509.Certificate) *x509.Certificate {
	cert.Extensions = cert.Extensions[:0]
	return cert
}

func makePoisonNonCritical(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension needs to be marked as critical.
	cert.Extensions = []pkix.Extension{{Id: ctPoisonExtensionOID, Critical: false, Value: asn1NullBytes}}
	return cert
}

func makePoisonNonNull(cert *x509.Certificate) *x509.Certificate {
	// Invalid as a pre-cert because poison extension is not ASN.1 NULL value.
	cert.Extensions = []pkix.Extension{{Id: ctPoisonExtensionOID, Critical: false, Value: []byte{0x42, 0x42, 0x42}}}
	return cert
}

func TestIsPrecertificate(t *testing.T) {
	var tests = []struct {
		desc        string
		cert        *x509.Certificate
		wantPrecert bool
		wantErr     bool
	}{
		{
			desc:        "valid-precert",
			cert:        pemToCert(t, testonly.PrecertPEMValid),
			wantPrecert: true,
		},
		{
			desc:        "valid-cert",
			cert:        pemToCert(t, testonly.CACertPEM),
			wantPrecert: false,
		},
		{
			desc:        "remove-exts-from-precert",
			cert:        wipeExtensions(pemToCert(t, testonly.PrecertPEMValid)),
			wantPrecert: false,
		},
		{
			desc:        "poison-non-critical",
			cert:        makePoisonNonCritical(pemToCert(t, testonly.PrecertPEMValid)),
			wantPrecert: false,
			wantErr:     true,
		},
		{
			desc:        "poison-non-null",
			cert:        makePoisonNonNull(pemToCert(t, testonly.PrecertPEMValid)),
			wantPrecert: false,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		gotPrecert, err := IsPrecertificate(test.cert)
		if err != nil {
			if !test.wantErr {
				t.Errorf("IsPrecertificate(%v)=%v,%v; want %v,nil", test.desc, gotPrecert, err, test.wantPrecert)
			}
			continue
		}
		if test.wantErr {
			t.Errorf("IsPrecertificate(%v)=%v,%v; want _,%v", test.desc, gotPrecert, err, test.wantErr)
		}
		if gotPrecert != test.wantPrecert {
			t.Errorf("IsPrecertificate(%v)=%v,%v; want %v,nil", test.desc, gotPrecert, err, test.wantPrecert)
		}
	}
}

func TestValidateChain(t *testing.T) {
	fakeCARoots := NewPEMCertPool()
	if !fakeCARoots.AppendCertsFromPEM([]byte(testonly.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	validateOpts := CertValidationOpts{
		trustedRoots: fakeCARoots,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	var tests = []struct {
		desc        string
		chain       [][]byte
		wantErr     bool
		wantPathLen int
	}{
		{
			desc:    "missing-intermediate-cert",
			chain:   pemsToDERChain(t, []string{testonly.LeafSignedByFakeIntermediateCertPEM}),
			wantErr: true,
		},
		{
			desc:    "wrong-cert-order",
			chain:   pemsToDERChain(t, []string{testonly.FakeIntermediateCertPEM, testonly.LeafSignedByFakeIntermediateCertPEM}),
			wantErr: true,
		},
		{
			desc:    "unrelated-cert-in-chain",
			chain:   pemsToDERChain(t, []string{testonly.FakeIntermediateCertPEM, testonly.TestCertPEM}),
			wantErr: true,
		},
		{
			desc:    "unrelated-cert-after-chain",
			chain:   pemsToDERChain(t, []string{testonly.LeafSignedByFakeIntermediateCertPEM, testonly.FakeIntermediateCertPEM, testonly.TestCertPEM}),
			wantErr: true,
		},
		{
			desc:        "valid-chain",
			chain:       pemsToDERChain(t, []string{testonly.LeafSignedByFakeIntermediateCertPEM, testonly.FakeIntermediateCertPEM}),
			wantPathLen: 3,
		},
	}
	for _, test := range tests {
		gotPath, err := ValidateChain(test.chain, validateOpts)
		if err != nil {
			if !test.wantErr {
				t.Errorf("ValidateChain(%v)=%v,%v; want _,nil", test.desc, gotPath, err)
			}
			continue
		}
		if test.wantErr {
			t.Errorf("ValidateChain(%v)=%v,%v; want _,non-nil", test.desc, gotPath, err)
		}
		if len(gotPath) != test.wantPathLen {
			t.Errorf("|ValidateChain(%v)|=%d; want %d", test.desc, len(gotPath), test.wantPathLen)
		}
	}
}

func TestCA(t *testing.T) {
	fakeCARoots := NewPEMCertPool()
	if !fakeCARoots.AppendCertsFromPEM([]byte(testonly.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	validateOpts := CertValidationOpts{
		trustedRoots: fakeCARoots,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chain := pemsToDERChain(t, []string{testonly.LeafSignedByFakeIntermediateCertPEM, testonly.FakeIntermediateCertPEM})
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("Failed to parse golden certificate DER: %v", err)
	}
	t.Logf("Cert expiry date: %v", leaf.NotAfter)

	var tests = []struct {
		desc    string
		chain   [][]byte
		caOnly  bool
		wantErr bool
	}{
		{
			desc:  "end-entity, allow non-CA",
			chain: chain,
		},
		{
			desc:    "end-entity, disallow non-CA",
			chain:   chain,
			caOnly:  true,
			wantErr: true,
		},
		{
			desc:  "intermediate, allow non-CA",
			chain: chain[1:],
		},
		{
			desc:   "intermediate, disallow non-CA",
			chain:  chain[1:],
			caOnly: true,
		},
	}
	for _, test := range tests {
		validateOpts.acceptOnlyCA = test.caOnly
		gotPath, err := ValidateChain(test.chain, validateOpts)
		if err != nil {
			if !test.wantErr {
				t.Errorf("ValidateChain(%v)=%v,%v; want _,nil", test.desc, gotPath, err)
			}
			continue
		}
		if test.wantErr {
			t.Errorf("ValidateChain(%v)=%v,%v; want _,non-nil", test.desc, gotPath, err)
		}
	}
}

func TestNotAfterRange(t *testing.T) {
	fakeCARoots := NewPEMCertPool()
	if !fakeCARoots.AppendCertsFromPEM([]byte(testonly.FakeCACertPEM)) {
		t.Fatal("failed to load fake root")
	}
	validateOpts := CertValidationOpts{
		trustedRoots:  fakeCARoots,
		rejectExpired: false,
		extKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chain := pemsToDERChain(t, []string{testonly.LeafSignedByFakeIntermediateCertPEM, testonly.FakeIntermediateCertPEM})

	var tests = []struct {
		desc          string
		chain         [][]byte
		notAfterStart time.Time
		notAfterLimit time.Time
		wantErr       bool
	}{
		{
			desc:  "valid-chain, no range",
			chain: chain,
		},
		{
			desc:          "valid-chain, valid range",
			chain:         chain,
			notAfterStart: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
			notAfterLimit: time.Date(2020, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			desc:          "before valid range",
			chain:         chain,
			notAfterStart: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:       true,
		},
		{
			desc:          "after valid range",
			chain:         chain,
			notAfterLimit: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:       true,
		},
	}
	for _, test := range tests {
		if !test.notAfterStart.IsZero() {
			validateOpts.notAfterStart = &test.notAfterStart
		}
		if !test.notAfterLimit.IsZero() {
			validateOpts.notAfterLimit = &test.notAfterLimit
		}
		gotPath, err := ValidateChain(test.chain, validateOpts)
		if err != nil {
			if !test.wantErr {
				t.Errorf("ValidateChain(%v)=%v,%v; want _,nil", test.desc, gotPath, err)
			}
			continue
		}
		if test.wantErr {
			t.Errorf("ValidateChain(%v)=%v,%v; want _,non-nil", test.desc, gotPath, err)
		}
	}
}

// Builds a chain of DER-encoded certs.
// Note: ordering is important
func pemsToDERChain(t *testing.T, pemCerts []string) [][]byte {
	t.Helper()
	chain := make([][]byte, 0, len(pemCerts))
	for _, pemCert := range pemCerts {
		cert := pemToCert(t, pemCert)
		chain = append(chain, cert.Raw)
	}
	return chain
}

func pemToCert(t *testing.T, pemData string) *x509.Certificate {
	t.Helper()
	bytes, rest := pem.Decode([]byte(pemData))
	if len(rest) > 0 {
		t.Fatalf("Extra data after PEM: %v", rest)
		return nil
	}

	cert, err := x509.ParseCertificate(bytes.Bytes)
	if err != nil {
		_, ok := err.(x509.NonFatalErrors)
		if !ok {
			t.Fatal(err)
			return nil
		}
	}

	return cert
}
