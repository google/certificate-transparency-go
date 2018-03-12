// Copyright 2018 Google Inc. All Rights Reserved.
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

package ctutil

import (
	"encoding/base64"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509util"
)

func TestLeafHash(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		want     string
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			want:     testdata.TestCertB64LeafHash,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			want:     testdata.TestPreCertB64LeafHash,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct ct.SignedCertificateTimestamp
		_, err = tls.Unmarshal(test.sct, &sct)
		if err != nil {
			t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
			continue
		}

		// Test LeafHash()
		wantSl, err := base64.StdEncoding.DecodeString(test.want)
		if err != nil {
			t.Fatalf("%s: error base64-decoding leaf hash %q: %s", test.desc, test.want, err)
		}
		var want [32]byte
		copy(want[:], wantSl)

		got, err := LeafHash(chain, &sct)
		if got != want || err != nil {
			t.Errorf("%s: LeafHash(_,_) = %v, %v, want %v, nil", test.desc, got, err, want)
		}

		// Test B64LeafHash()
		gotB64, err := B64LeafHash(chain, &sct)
		if gotB64 != test.want || err != nil {
			t.Errorf("%s: B64LeafHash(_,_) = %v, %v, want %v, nil", test.desc, gotB64, err, test.want)
		}
	}
}

func TestLeafHashErrors(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
	}{
		{
			desc:     "empty chain",
			chainPEM: "",
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "nil sct",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      nil,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct *ct.SignedCertificateTimestamp
		if test.sct != nil {
			sct = &ct.SignedCertificateTimestamp{}
			_, err = tls.Unmarshal(test.sct, sct)
			if err != nil {
				t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
				continue
			}
		}

		// Test LeafHash()
		got, err := LeafHash(chain, sct)
		if got != emptyHash || err == nil {
			t.Errorf("%s: LeafHash(_,_) = %s, %v, want %v, error", test.desc, got, err, emptyHash)
		}

		// Test B64LeafHash()
		gotB64, err := B64LeafHash(chain, sct)
		if gotB64 != "" || err == nil {
			t.Errorf("%s: B64LeafHash(_,_) = %s, %v, want \"\", error", test.desc, gotB64, err)
		}
	}
}

func TestVerifySCT(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		wantErr  bool
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "bad SCT",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := x509util.CertificatesFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct ct.SignedCertificateTimestamp
		_, err = tls.Unmarshal(test.sct, &sct)
		if err != nil {
			t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
			continue
		}

		// Test VerifySCT()
		pk, err := ParseB64PublicKey(testdata.LogPublicKeyB64)
		if err != nil {
			t.Errorf("%s: error parsing public key: %s", test.desc, err)
		}

		err = VerifySCT(pk, chain, &sct)
		if gotErr := (err != nil); gotErr != test.wantErr {
			t.Errorf("%s: VerifySCT(_,_,_) = %v, want error? %t", test.desc, err, test.wantErr)
		}
	}
}
