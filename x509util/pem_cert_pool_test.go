// Copyright 2016 Google LLC. All Rights Reserved.
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
	"encoding/pem"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

func TestLoadSingleCertFromPEMs(t *testing.T) {
	for _, p := range []string{pemCACert, pemCACertWithOtherStuff, pemCACertDuplicated} {
		pool := x509util.NewPEMCertPool()

		ok := pool.AppendCertsFromPEM([]byte(p))
		if !ok {
			t.Fatal("Expected to append a certificate ok")
		}
		if got, want := len(pool.Subjects()), 1; got != want {
			t.Fatalf("Got %d cert(s) in the pool, expected %d", got, want)
		}
	}
}

func TestBadOrEmptyCertificateRejected(t *testing.T) {
	for _, p := range []string{pemUnknownBlockType, pemCACertBad} {
		pool := x509util.NewPEMCertPool()

		ok := pool.AppendCertsFromPEM([]byte(p))
		if ok {
			t.Fatal("Expected appending no certs")
		}
		if got, want := len(pool.Subjects()), 0; got != want {
			t.Fatalf("Got %d cert(s) in pool, expected %d", got, want)
		}
	}
}

func TestLoadMultipleCertsFromPEM(t *testing.T) {
	pool := x509util.NewPEMCertPool()

	ok := pool.AppendCertsFromPEM([]byte(pemCACertMultiple))
	if !ok {
		t.Fatal("Rejected valid multiple certs")
	}
	if got, want := len(pool.Subjects()), 2; got != want {
		t.Fatalf("Got %d certs in pool, expected %d", got, want)
	}
}

func TestIncluded(t *testing.T) {
	certs := [2]*x509.Certificate{parsePEM(t, pemCACert), parsePEM(t, pemFakeCACert)}

	// Note: tests are cumulative
	tests := []struct {
		cert *x509.Certificate
		want [2]bool
	}{
		{cert: nil, want: [2]bool{false, false}},
		{cert: nil, want: [2]bool{false, false}},
		{cert: certs[0], want: [2]bool{true, false}},
		{cert: nil, want: [2]bool{true, false}},
		{cert: certs[0], want: [2]bool{true, false}},
		{cert: certs[1], want: [2]bool{true, true}},
		{cert: nil, want: [2]bool{true, true}},
		{cert: certs[1], want: [2]bool{true, true}},
	}

	pool := x509util.NewPEMCertPool()
	for _, test := range tests {
		if test.cert != nil {
			pool.AddCert(test.cert)
		}
		for i, cert := range certs {
			got := pool.Included(cert)
			if got != test.want[i] {
				t.Errorf("pool.Included(cert[%d])=%v, want %v", i, got, test.want[i])
			}
		}
	}
}

func parsePEM(t *testing.T, pemCert string) *x509.Certificate {
	var block *pem.Block
	block, _ = pem.Decode([]byte(pemCert))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		t.Fatal("No PEM data found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if x509.IsFatal(err) {
		t.Fatalf("Failed to parse PEM certificate: %v", err)
	}
	return cert
}
