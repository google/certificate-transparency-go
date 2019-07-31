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
package ctpolicy

import (
	"testing"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/kylelemons/godebug/pretty"
)

func wantedGroups(goog int, nonGoog int, base int, minusBob bool) LogPolicyData {
	gi := LogPolicyData{
		"Google-operated": {
			Name: "Google-operated",
			LogURLs: map[string]bool{
				"https://ct.googleapis.com/logs/argon2020/": true,
				"https://ct.googleapis.com/aviator/":        true,
				"https://ct.googleapis.com/icarus/":         true,
				"https://ct.googleapis.com/rocketeer/":      true,
				"https://ct.googleapis.com/racketeer/":      true,
			},
			MinInclusions: goog,
			IsBase:        false,
			LogWeights: map[string]float32{
				"https://ct.googleapis.com/logs/argon2020/": 1.0,
				"https://ct.googleapis.com/aviator/":        1.0,
				"https://ct.googleapis.com/icarus/":         1.0,
				"https://ct.googleapis.com/rocketeer/":      1.0,
				"https://ct.googleapis.com/racketeer/":      1.0,
			},
		},
		"Non-Google-operated": {
			Name: "Non-Google-operated",
			LogURLs: map[string]bool{
				"https://log.bob.io": true,
			},
			MinInclusions: nonGoog,
			IsBase:        false,
			LogWeights: map[string]float32{
				"https://log.bob.io": 1.0,
			},
		},
		BaseName: {
			Name: BaseName,
			LogURLs: map[string]bool{
				"https://ct.googleapis.com/logs/argon2020/": true,
				"https://ct.googleapis.com/aviator/":        true,
				"https://ct.googleapis.com/icarus/":         true,
				"https://ct.googleapis.com/rocketeer/":      true,
				"https://ct.googleapis.com/racketeer/":      true,
				"https://log.bob.io":                        true,
			},
			MinInclusions: base,
			IsBase:        true,
			LogWeights: map[string]float32{
				"https://ct.googleapis.com/logs/argon2020/": 1.0,
				"https://ct.googleapis.com/aviator/":        1.0,
				"https://ct.googleapis.com/icarus/":         1.0,
				"https://ct.googleapis.com/rocketeer/":      1.0,
				"https://ct.googleapis.com/racketeer/":      1.0,
				"https://log.bob.io":                        1.0,
			},
		},
	}
	if minusBob {
		delete(gi[BaseName].LogURLs, "https://log.bob.io")
		delete(gi[BaseName].LogWeights, "https://log.bob.io")
		delete(gi["Non-Google-operated"].LogURLs, "https://log.bob.io")
		delete(gi["Non-Google-operated"].LogWeights, "https://log.bob.io")
	}
	return gi
}

func TestCheckChromePolicy(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want LogPolicyData
	}{
		{
			name: "Short",
			cert: getTestCertPEMShort(),
			want: wantedGroups(1, 1, 2, false),
		},
		{
			name: "2-year",
			cert: getTestCertPEM2Years(),
			want: wantedGroups(1, 1, 3, false),
		},
		{
			name: "3-year",
			cert: getTestCertPEM3Years(),
			want: wantedGroups(1, 1, 4, false),
		},
		{
			name: "Long",
			cert: getTestCertPEMLongOriginal(),
			want: wantedGroups(1, 1, 5, false),
		},
	}

	var policy ChromeCTPolicy
	sampleLogList := sampleLogList(t)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := policy.LogsByGroup(test.cert, sampleLogList)
			if diff := pretty.Compare(test.want, got); diff != "" {
				t.Errorf("LogsByGroup: (-want +got)\n%s", diff)
			}
			if err != nil {
				t.Errorf("LogsByGroup returned an error when not expected: %v", err)
			}
		})
	}
}

func TestCheckChromePolicyWarnings(t *testing.T) {
	tests := []struct {
		name    string
		cert    *x509.Certificate
		want    LogPolicyData
		warning string
	}{
		{
			name:    "Short",
			cert:    getTestCertPEMShort(),
			want:    LogPolicyData{},
			warning: "trying to assign 1 minimal inclusion number while only 0 logs are part of group \"Non-Google-operated\"",
		},
		{
			name:    "2-year",
			cert:    getTestCertPEM2Years(),
			want:    LogPolicyData{},
			warning: "trying to assign 1 minimal inclusion number while only 0 logs are part of group \"Non-Google-operated\"",
		},
		{
			name:    "3-year",
			cert:    getTestCertPEM3Years(),
			want:    LogPolicyData{},
			warning: "trying to assign 1 minimal inclusion number while only 0 logs are part of group \"Non-Google-operated\"",
		},
		{
			name:    "Long",
			cert:    getTestCertPEMLongOriginal(),
			want:    LogPolicyData{},
			warning: "trying to assign 1 minimal inclusion number while only 0 logs are part of group \"Non-Google-operated\"",
		},
	}

	var policy ChromeCTPolicy
	sampleLogList := sampleLogList(t)
	// Removing Bob-log.
	sampleLogList.Operators = sampleLogList.Operators[:1]

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			got, err := policy.LogsByGroup(test.cert, sampleLogList)
			if diff := pretty.Compare(test.want, got); diff != "" {
				t.Errorf("LogsByGroup: (-want +got)\n%s", diff)
			}
			if err == nil && len(test.warning) > 0 {
				t.Errorf("LogsByGroup returned no error when expected")
			} else if err != nil {
				if err.Error() != test.warning {
					t.Errorf("LogsByGroup returned error message %q while expected %q", err.Error(), test.warning)
				}
			}
		})
	}
}
