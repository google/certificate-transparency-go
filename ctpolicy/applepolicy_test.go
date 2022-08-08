// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

func wantedAppleGroups(count int) LogPolicyData {
	gi := LogPolicyData{
		BaseName: {
			Name: BaseName,
			LogURLs: map[string]bool{
				"https://ct.googleapis.com/aviator/":        true,
				"https://ct.googleapis.com/icarus/":         true,
				"https://ct.googleapis.com/rocketeer/":      true,
				"https://ct.googleapis.com/racketeer/":      true,
				"https://ct.googleapis.com/logs/argon2020/": true,
				"https://log.bob.io":                        true,
			},
			MinInclusions: count,
			IsBase:        true,
			LogWeights: map[string]float32{
				"https://ct.googleapis.com/aviator/":        1.0,
				"https://ct.googleapis.com/icarus/":         1.0,
				"https://ct.googleapis.com/rocketeer/":      1.0,
				"https://ct.googleapis.com/racketeer/":      1.0,
				"https://ct.googleapis.com/logs/argon2020/": 1.0,
				"https://log.bob.io":                        1.0,
			},
		},
	}
	return gi
}

func TestCheckApplePolicy(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want LogPolicyData
	}{
		{
			name: "Short",
			cert: getTestCertPEMShort(),
			want: wantedAppleGroups(2),
		},
		{
			name: "2-year",
			cert: getTestCertPEM2Years(),
			want: wantedAppleGroups(3),
		},
		{
			name: "3-year",
			cert: getTestCertPEM3Years(),
			want: wantedAppleGroups(4),
		},
		{
			name: "Long",
			cert: getTestCertPEMLongOriginal(),
			want: wantedAppleGroups(5),
		},
	}

	var policy AppleCTPolicy
	sampleLogList := sampleLogList(t)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			groups, err := policy.LogsByGroup(test.cert, sampleLogList)
			if err != nil {
				t.Errorf("LogsByGroup returned an error: %v", err)
			}
			if diff := pretty.Compare(test.want, groups); diff != "" {
				t.Errorf("LogsByGroup: (-want +got)\n%s", diff)
			}
		})
	}
}
