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

package loglist

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mohae/deepcopy"
)

func pprint(stringList []string) string {
	var pretty string
	if buf, err := json.MarshalIndent(stringList, "", "  "); err == nil {
		pretty = string(buf)
	} else {
		pretty = fmt.Sprintf("%v", stringList)
	}
	return pretty
}

func TestCheckOperatorsDiff(t *testing.T) {
	var tests = []struct {
		name         string
		branch_ll    LogList
		wantWarnings []string
	}{
		{
			name: "Equal",
			branch_ll: LogList{
				Operators: []Operator{
					{ID: 0, Name: "Google"},
					{ID: 1, Name: "Bob's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings: []string{},
		},
		{
			name: "ShuffledRenamed",
			branch_ll: LogList{
				Operators: []Operator{
					{ID: 1, Name: "Bob's CT Log Shop+"},
					{ID: 0, Name: "Google"},
				}, Logs: []Log{},
			},
			wantWarnings: []string{},
		},
		{
			name: "Missing",
			branch_ll: LogList{
				Operators: []Operator{
					{ID: 1, Name: "Bob's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings: []string{"Operator \"Google\" id=0 present at master log list but missing at branch."},
		},
		{
			name: "Added",
			branch_ll: LogList{
				Operators: []Operator{
					{ID: 0, Name: "Google"},
					{ID: 1, Name: "Bob's CT Log Shop"},
					{ID: 2, Name: "Alice's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl := warningList{warnings: []string{}}
			checkMasterOpsMatchBranch(&sampleLogList, &test.branch_ll, &wl)
			if !reflect.DeepEqual(wl.warnings, test.wantWarnings) {
				t.Errorf("checkOperators: got '%v', want warnings '%v'", wl.warnings,
					test.wantWarnings)
			}
		})
	}
}

func TestCheckLogPairEquivalence(t *testing.T) {
	type logPair struct {
		log1         Log
		log2         Log
		wantWarnings []string
	}
	var tests = make(map[string]*logPair)
	tests["Equal"] = &logPair{
		log1:         deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		log2:         deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		wantWarnings: []string{},
	}
	tests["KeyURLMismatch"] = &logPair{
		log1: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		log2: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		wantWarnings: []string{
			"Log \"Google 'Aviator' log\" and log \"Google 'Aviator' log\" have different keys.",
			"URL mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\": " +
				"ct.googleapis.com/aviator/ != ct.googleapis.com/icarus/.",
		},
	}
	tests["KeyURLMismatch"].log2.Key = sampleLogList.Logs[1].Key
	tests["KeyURLMismatch"].log2.URL = sampleLogList.Logs[1].URL

	tests["TimingsMismatch"] = &logPair{
		log1: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		log2: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		wantWarnings: []string{
			"Maximum merge delay mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\": " +
				"86400 != 86401.",
			"Disqualified-at-timing mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\": ",
		},
	}
	tests["TimingsMismatch"].log2.MaximumMergeDelay = 86401
	tests["TimingsMismatch"].log2.DisqualifiedAt = 1460678400

	tests["OperatorsDNSMismatch"] = &logPair{
		log1: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		log2: deepcopy.Copy(sampleLogList.Logs[0]).(Log),
		wantWarnings: []string{
			"Operators mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\".",
			"DNS API mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\": " +
				"aviator.ct.googleapis.com != icarus.ct.googleapis.com.",
		},
	}
	tests["OperatorsDNSMismatch"].log2.OperatedBy =
		append(tests["OperatorsDNSMismatch"].log2.OperatedBy, 1)
	tests["OperatorsDNSMismatch"].log2.DNSAPIEndpoint = sampleLogList.Logs[1].DNSAPIEndpoint
	for testname, test := range tests {
		t.Run(testname, func(t *testing.T) {
			wl := warningList{warnings: []string{}}
			test.log1.checkEquivalence(&test.log2, &wl)
			printMismatchIfAny(t, wl.warnings, test.wantWarnings, "CheckLogs:")
		})
	}
}

func TestCheckBranch(t *testing.T) {
	type logListTest struct {
		branchList   LogList
		wantWarnings []string
		wantError    bool
	}
	var tests = make(map[string]*logListTest)
	tests["Copy"] = &logListTest{
		branchList:   deepcopy.Copy(sampleLogList).(LogList),
		wantWarnings: []string{},
	}

	tests["OneMatch"] = &logListTest{
		branchList:   deepcopy.Copy(sampleLogList).(LogList),
		wantWarnings: []string{},
	}
	tests["OneMatch"].branchList.Logs = tests["OneMatch"].branchList.Logs[0:1]

	// Operator exclusion is restricted.
	tests["OneMatchOperatorMiss"] = &logListTest{
		branchList: deepcopy.Copy(sampleLogList).(LogList),
		wantWarnings: []string{
			"Operator \"Bob's CT Log Shop\" id=1 present at master log list but missing at branch."},
		wantError: true,
	}
	tests["OneMatchOperatorMiss"].branchList.Logs =
		tests["OneMatchOperatorMiss"].branchList.Logs[0:1]
	tests["OneMatchOperatorMiss"].branchList.Operators =
		tests["OneMatchOperatorMiss"].branchList.Operators[0:1]

	tests["Shuffled"] = &logListTest{
		branchList:   deepcopy.Copy(sampleLogList).(LogList),
		wantWarnings: []string{},
	}
	tests["Shuffled"].branchList.Logs[0] = deepcopy.Copy(sampleLogList.Logs[3]).(Log)
	tests["Shuffled"].branchList.Logs[3] = deepcopy.Copy(sampleLogList.Logs[0]).(Log)
	tests["Shuffled"].branchList.Operators[0] = deepcopy.Copy(sampleLogList.Operators[1]).(Operator)
	tests["Shuffled"].branchList.Operators[1] = deepcopy.Copy(sampleLogList.Operators[0]).(Operator)

	tests["OperatorsMess"] = &logListTest{
		branchList: deepcopy.Copy(sampleLogList).(LogList),
		wantWarnings: []string{
			"Operator \"Bob's CT Log Shop\" id=1 present at master log list but missing at branch.",
			"Operators mismatch for logs \"Google 'Aviator' log\" and \"Google 'Aviator' log\"."},
		wantError: true,
	}
	tests["OperatorsMess"].branchList.Logs[0].OperatedBy = []int{1}
	tests["OperatorsMess"].branchList.Operators =
		tests["OperatorsMess"].branchList.Operators[0:1]

	for testname, test := range tests {
		t.Run(testname, func(t *testing.T) {
			wl, err := sampleLogList.CheckBranch(&test.branchList)
			if test.wantError != (err != nil) {
				t.Errorf("CheckBranch %s: error status mismatch.", testname)
			}
			printMismatchIfAny(t, wl, test.wantWarnings, "CheckBranch " + testname + ":")
		})
	}
}

func printMismatchIfAny(t *testing.T, got []string, want []string, lineStart string) {
	wMismatchIds := make([]int, 0)
	for i := 0; i < len(got) || i < len(want); i++ {
		if i >= len(got) || i >= len(want ) || !strings.Contains(got[i], want[i]) {
			wMismatchIds = append(wMismatchIds, i)
		}
	}
	if len(wMismatchIds) > 0 {
		t.Errorf("%s got '%v', want warnings '%v'.\n %v-st/d/th warning mismatch.",
			lineStart, got, want, wMismatchIds)
	}
}
