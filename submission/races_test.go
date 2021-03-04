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

package submission

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
)

func testdataSCT() *ct.SignedCertificateTimestamp {
	var sct ct.SignedCertificateTimestamp
	tls.Unmarshal(testdata.TestPreCertProof, &sct)
	return &sct
}

type mockSubmitter struct {
	fixedDelay              map[byte]time.Duration
	firstLetterURLReqNumber map[byte]int
	mu                      sync.Mutex
}

// Each request within same Log-group gets additional sleep period.
func (ms *mockSubmitter) SubmitToLog(_ context.Context, logURL string, _ []ct.ASN1Cert, _ bool) (*ct.SignedCertificateTimestamp, error) {
	ms.mu.Lock()
	reqNum := ms.firstLetterURLReqNumber[logURL[0]]
	ms.firstLetterURLReqNumber[logURL[0]]++
	ms.mu.Unlock()
	sct := testdataSCT()
	time.Sleep(time.Duration(500*reqNum)*time.Millisecond + ms.fixedDelay[logURL[0]])
	return sct, nil
}

func evaluateSCTs(t *testing.T, got []*AssignedSCT, trail map[string]int) {
	t.Helper()
	for _, sct := range got {
		if _, ok := trail[ctpolicy.BaseName]; ok {
			trail[ctpolicy.BaseName]--
			if trail[sct.LogURL[0:1]] > 0 {
				trail[sct.LogURL[0:1]]--
			}
		} else {
			trail[sct.LogURL[0:1]]--
		}
	}
	for groupName, count := range trail {
		// It's possible to get more SCTs for Log-group than minimally-required.
		// If group completion happened in-between Log-request and response. Or in case of group-intersection.
		if count > 0 {
			for _, s := range got {
				t.Errorf("%v\n", s.LogURL)
			}
			t.Errorf("Got %v. Received %d less SCTs from group %q than expected", got, count, groupName)
		} else if count < 0 {
			for _, s := range got {
				t.Errorf("%v\n", s.LogURL)
			}
			t.Errorf("Got %v. Received %d more SCTs from group %q than expected", got, -count, groupName)
		}
	}
}

func TestGetSCTs(t *testing.T) {
	testCases := []struct {
		name        string
		sbMock      Submitter
		groups      ctpolicy.LogPolicyData
		resultTrail map[string]int
		errRegexp   *regexp.Regexp
	}{
		{
			name:   "singleGroupOneSCT",
			sbMock: &mockSubmitter{fixedDelay: map[byte]time.Duration{'a': 0}, firstLetterURLReqNumber: make(map[byte]int)},
			groups: ctpolicy.LogPolicyData{
				"a": {
					Name:          "a",
					LogURLs:       map[string]bool{"a1.com": true, "a2.com": true},
					MinInclusions: 1,
					IsBase:        false,
					LogWeights:    map[string]float32{"a1.com": 1.0, "a2.com": 1.0},
				},
			},
			resultTrail: map[string]int{"a": 1},
		},
		{
			name:   "singleGroupMultiSCT",
			sbMock: &mockSubmitter{fixedDelay: map[byte]time.Duration{'a': 0}, firstLetterURLReqNumber: make(map[byte]int)},
			groups: ctpolicy.LogPolicyData{
				"a": {
					Name:          "a",
					LogURLs:       map[string]bool{"a1.com": true, "a2.com": true, "a3.com": true, "a4.com": true, "a5.com": true},
					MinInclusions: 3,
					IsBase:        false,
					LogWeights:    map[string]float32{"a1.com": 1.0, "a2.com": 1.0, "a3.com": 1.0, "a4.com": 1.0, "a5.com": 1.0},
				},
			},
			resultTrail: map[string]int{"a": 3},
		},
		{
			name:   "chromeLike",
			sbMock: &mockSubmitter{fixedDelay: map[byte]time.Duration{'a': 0, 'b': 2 * time.Second}, firstLetterURLReqNumber: make(map[byte]int)},
			groups: ctpolicy.LogPolicyData{
				"a": {
					Name:          "a",
					LogURLs:       map[string]bool{"a1.com": true, "a2.com": true, "a3.com": true, "a4.com": true},
					MinInclusions: 1,
					IsBase:        false,
					LogWeights:    map[string]float32{"a1.com": 1.0, "a2.com": 1.0, "a3.com": 1.0, "a4.com": 1.0},
				},
				"b": {
					Name:          "b",
					LogURLs:       map[string]bool{"b1.com": true, "b2.com": true, "b3.com": true, "b4.com": true},
					MinInclusions: 1,
					IsBase:        false,
					LogWeights:    map[string]float32{"b1.com": 1.0, "b2.com": 1.0, "b3.com": 1.0, "b4.com": 1.0},
				},
				ctpolicy.BaseName: {
					Name:          ctpolicy.BaseName,
					LogURLs:       map[string]bool{"a1.com": true, "a2.com": true, "a3.com": true, "a4.com": true, "b1.com": true, "b2.com": true, "b3.com": true, "b4.com": true},
					MinInclusions: 5,
					IsBase:        true,
					LogWeights:    map[string]float32{"a1.com": 1.0, "a2.com": 1.0, "a3.com": 1.0, "a4.com": 1.0, "b1.com": 1.0, "b2.com": 1.0, "b3.com": 1.0, "b4.com": 1.0},
				},
			},
			resultTrail: map[string]int{"a": 1, "b": 1, ctpolicy.BaseName: 5},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res, err := GetSCTs(ctx, tc.sbMock, []ct.ASN1Cert{{Data: []byte{0}}}, true, tc.groups)
			if tc.resultTrail != nil {
				evaluateSCTs(t, res, tc.resultTrail)
			}
			if tc.errRegexp == nil {
				if err != nil {
					t.Fatalf("GetSCTs() got err=%q want nil", err)
				}
				return
			}
			// If we reach here then we expected an error.
			if err == nil {
				t.Fatalf("GetSCTs() got err=nil want err matching: %q", tc.errRegexp)
			}
			if !tc.errRegexp.MatchString(err.Error()) {
				t.Errorf("GetSCTs() got err=%q want err matching: %q", err, tc.errRegexp)
			}
		})
	}
}
