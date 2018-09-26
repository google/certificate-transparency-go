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
	"reflect"
	"testing"
)

func TestCheckOperatorsDiff(t *testing.T) {
	var tests = []struct {
		name string
		branch_ll	LogList
		wantWarnings []string
	}{
		{
			name: "Equal",
			branch_ll : LogList {
				Operators: []Operator{
					{ID: 0, Name: "Google"},
					{ID: 1, Name: "Bob's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings:   []string{},
		},
		{
			name: "Shuffled",
			branch_ll : LogList {
				Operators: []Operator{
					{ID: 1, Name: "Bob's CT Log Shop"},
					{ID: 0, Name: "Google"},
				}, Logs: []Log{},
			},
			wantWarnings:   []string{"Operators lists are not identical"},
		},
		{
			name: "Missing",
			branch_ll : LogList {
				Operators: []Operator{
					{ID: 1, Name: "Bob's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings:   []string{"Operators lists are not identical"},
		},
		{
			name: "Added",
			branch_ll : LogList {
				Operators: []Operator{
					{ID: 0, Name: "Google"},
					{ID: 1, Name: "Bob's CT Log Shop"},
					{ID: 2, Name: "Alice's CT Log Shop"},
				}, Logs: []Log{},
			},
			wantWarnings:   []string{"Operators lists are not identical"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl := warningList{warnings: []string{}}
			checkOperators(&SampleLogList, &test.branch_ll, &wl)
			if !reflect.DeepEqual(wl.warnings, test.wantWarnings) {
				t.Errorf("checkOperators: got '%v', want warnings '%v'", wl.warnings,
				         test.wantWarnings)
			}
		})
	}
}

func TestCheckLogsDiff(t *testing.T) {
	var tests = []struct {
		name string
		branch_ll	LogList
		wantWarnings []string
	}{
		{
			name: "OneMatch",
			branch_ll : LogList {
				Operators: []Operator{},
				Logs: []Log{
					{
						Description:       "Google 'Aviator' log",
						Key:               deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q=="),
						URL:               "ct.googleapis.com/aviator/",
						MaximumMergeDelay: 86400,
						OperatedBy:        []int{0},
						FinalSTH: &STH{
							TreeSize:          46466472,
							Timestamp:         1480512258330,
							SHA256RootHash:    deb64("LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA="),
							TreeHeadSignature: deb64("BAMASDBGAiEA/M0Nvt77aNe+9eYbKsv6rRpTzFTKa5CGqb56ea4hnt8CIQCJDE7pL6xgAewMd5i3G1lrBWgFooT2kd3+zliEz5Rw8w=="),
						},
						DNSAPIEndpoint: "aviator.ct.googleapis.com",
					},
				},
			},
			wantWarnings:   []string{},
		},
		{
			name: "Shuffled",
			branch_ll : LogList {
				Operators: []Operator{},
				Logs: []Log{},
			},
			wantWarnings:   []string{"Operators lists are not identical"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wl := warningList{warnings: []string{}}
			checkLogs(&SampleLogList, &test.branch_ll, &wl)
			if !reflect.DeepEqual(wl.warnings, test.wantWarnings) {
				t.Errorf("checkLogs: got '%v', want warnings '%v'", wl.warnings,
				         test.wantWarnings)
			}
		})
	}
}


