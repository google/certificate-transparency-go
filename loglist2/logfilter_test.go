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
package loglist2

import (
	"testing"

	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"

	"github.com/kylelemons/godebug/pretty"
)

func subLogList(logURLs map[string]bool) LogList {
	var ll LogList
	for _, op := range sampleLogList.Operators {
		opCopy := *op
		opCopy.Logs = []*Log{}
		for _, l := range op.Logs {
			if logURLs[l.URL] {
				opCopy.Logs = append(opCopy.Logs, l)
			}
		}
		if len(opCopy.Logs) > 0 {
			ll.Operators = append(ll.Operators, &opCopy)
		}
	}
	return ll
}

func TestSelectUsable(t *testing.T) {
	tests := []struct {
		name string
		in   LogList
		want LogList
	}{
		{
			name: "Sample",
			in:   sampleLogList,
			want: subLogList(map[string]bool{"ct.googleapis.com/icarus/": true}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.in.SelectUsable()
			if diff := pretty.Compare(got, test.want); diff != "" {
				t.Errorf("Extracting active logs out of %v diff: (-got + want)\n%s", test.in, diff)
			}
		})
	}
}

func certChain() []*x509.Certificate {
	cert, _ := x509util.CertificateFromPEM([]byte(testdata.TestPreCertPEM))
	caCert, _ := x509util.CertificateFromPEM([]byte(testdata.CACertPEM))
	return []*x509.Certificate{cert, caCert}
}

func singleCert() []*x509.Certificate {
	cert, _ := x509util.CertificateFromPEM([]byte(testdata.TestPreCertPEM))
	return []*x509.Certificate{cert}
}

func artificialRoots(source string) LogRoots {
	roots := LogRoots{
		"log.bob.io":                           ctfe.NewPEMCertPool(),
		"https://ct.googleapis.com/racketeer/": ctfe.NewPEMCertPool(),
		"https://ct.googleapis.com/rocketeer/": ctfe.NewPEMCertPool(),
		"https://ct.googleapis.com/aviator/":   ctfe.NewPEMCertPool(),
	}
	roots["log.bob.io"].AppendCertsFromPEM([]byte(source))
	return roots
}

func TestRootCompatible(t *testing.T) {
	tests := []struct {
		name  string
		in    LogList
		chain []*x509.Certificate
		roots LogRoots
		want  LogList
	}{
		{
			name:  "RootedChain",
			in:    sampleLogList,
			chain: certChain(),
			roots: artificialRoots(testdata.CACertPEM),
			want:  subLogList(map[string]bool{"log.bob.io": true, "https://ct.googleapis.com/icarus/": true}), // icarus has no root info.
		},
		{
			name:  "RootedChainNoRootAccepted",
			in:    sampleLogList,
			chain: certChain(),
			roots: artificialRoots(testdata.TestPreCertPEM),
			want:  subLogList(map[string]bool{"https://ct.googleapis.com/icarus/": true}), // icarus has no root info.
		},
		{
			name:  "UnRootedChain",
			in:    sampleLogList,
			chain: singleCert(),
			roots: artificialRoots(testdata.CACertPEM),
			want:  subLogList(map[string]bool{}),
		},
		{
			name:  "EmptyChain",
			in:    sampleLogList,
			chain: []*x509.Certificate{},
			roots: artificialRoots(testdata.CACertPEM),
			want:  subLogList(map[string]bool{"https://ct.googleapis.com/icarus/": true}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.in.RootCompatible(test.chain, test.roots)
			if diff := pretty.Compare(got, test.want); diff != "" {
				t.Errorf("Getting compatible logs diff: (-got +want)\n%s", diff)
			}
		})
	}
}
