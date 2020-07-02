// Copyright 2018 Google LLC. All Rights Reserved.
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
package loglist

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
	ll.Operators = sampleLogList.Operators
	for _, l := range sampleLogList.Logs {
		if logURLs[l.URL] {
			ll.Logs = append(ll.Logs, l)
		}
	}
	return ll
}

func TestActiveLogs(t *testing.T) {
	tests := []struct {
		name string
		in   LogList
		want LogList
	}{
		{
			name: "Sample",
			in:   sampleLogList,
			want: subLogList(map[string]bool{"ct.googleapis.com/icarus/": true, "ct.googleapis.com/rocketeer/": true, "ct.googleapis.com/racketeer/": true}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.in.ActiveLogs()
			if diff := pretty.Compare(got, test.want); diff != "" {
				t.Errorf("Extracting active logs out of %v diff: (-got + want)\n%s", test.in, diff)
			}
		})
	}
}

func artificialRoots(source string) LogRoots {
	roots := LogRoots{
		"log.bob.io":                   ctfe.NewPEMCertPool(),
		"ct.googleapis.com/racketeer/": ctfe.NewPEMCertPool(),
		"ct.googleapis.com/rocketeer/": ctfe.NewPEMCertPool(),
		"ct.googleapis.com/aviator/":   ctfe.NewPEMCertPool(),
	}
	roots["log.bob.io"].AppendCertsFromPEM([]byte(source))
	return roots
}

func TestCompatible(t *testing.T) {
	cert, _ := x509util.CertificateFromPEM([]byte(testdata.TestPreCertPEM))
	caCert, _ := x509util.CertificateFromPEM([]byte(testdata.CACertPEM))

	tests := []struct {
		name     string
		in       LogList
		cert     *x509.Certificate
		certRoot *x509.Certificate
		roots    LogRoots
		want     LogList
	}{
		{
			name:     "RootedChain",
			in:       sampleLogList,
			cert:     cert,
			certRoot: caCert,
			roots:    artificialRoots(testdata.CACertPEM),
			want:     subLogList(map[string]bool{"log.bob.io": true, "ct.googleapis.com/icarus/": true}), // icarus has no root info.
		},
		{
			name:     "RootedChainNoRootAccepted",
			in:       sampleLogList,
			cert:     cert,
			certRoot: caCert,
			roots:    artificialRoots(testdata.TestPreCertPEM),
			want:     subLogList(map[string]bool{"ct.googleapis.com/icarus/": true}), // icarus has no root info.
		},
		{
			name:     "UnRootedChain",
			in:       sampleLogList,
			cert:     cert,
			certRoot: cert,
			roots:    artificialRoots(testdata.CACertPEM),
			want:     subLogList(map[string]bool{}),
		},
		{
			name:     "EmptyChain",
			in:       sampleLogList,
			cert:     nil,
			certRoot: nil,
			roots:    artificialRoots(testdata.CACertPEM),
			want:     subLogList(map[string]bool{"ct.googleapis.com/icarus/": true}), // icarus has no root info.
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.in.Compatible(test.cert, test.certRoot, test.roots)
			if diff := pretty.Compare(got, test.want); diff != "" {
				t.Errorf("Getting compatible logs diff: (-got +want)\n%s", diff)
			}
		})
	}
}
