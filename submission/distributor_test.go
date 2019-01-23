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
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/testdata"
)

// buildNoLogClient is LogClientBuilder that always fails.
func buildNoLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return nil, errors.New("bad client builder")
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
			name:      "BadLog",
			ll:        sampleLogList(t),
			lcBuilder: buildLogClient,
			errRegexp: regexp.MustCompile("Failed to create log client for .*racketeer.*"),
		},

		{
			name:      "ValidLogClients",
			ll:        sampleValidLogList(t),
			lcBuilder: buildLogClient,
		},
		{
			name:      "NoLogClients",
			lcBuilder: buildNoLogClient,
			ll:        sampleValidLogList(t),
			errRegexp: regexp.MustCompile("Failed to create log client.*"),
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
			if (tc.errRegexp == nil) != (err == nil) {
				t.Errorf("Expected error state does not match produced one.")
			} else if tc.errRegexp != nil {
				if !tc.errRegexp.MatchString(err.Error()) {
					t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
				}
			}
		})
	}
}
