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
package ctpolicy

import (
	"testing"
)

func TestWeightedRandomSampleDef(t *testing.T) {
	tests := []struct {
		name     string
		weights  map[string]float32
		wantItem string
		wantErr  bool
	}{
		{
			name:     "OneNegativeWeight",
			weights:  map[string]float32{"a": 0.5, "b": -0.5, "c": 3.0},
			wantItem: "",
			wantErr:  true,
		},
		{
			name:     "AllZeroWeights",
			weights:  map[string]float32{"a": 0.0, "b": 0.0, "c": 0.0},
			wantItem: "",
			wantErr:  true,
		},
		{
			name:     "OneNonZeroWeights",
			weights:  map[string]float32{"a": 0.0, "b": 4.0, "c": 0.0},
			wantItem: "b",
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotItem, err := weightedRandomSample(tc.weights)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("weightedRandomSample(%v) = (_, error: %v), want err? %t", tc.weights, err, tc.wantErr)
			}
			if gotItem != tc.wantItem {
				t.Errorf("weightedRandomSample(%v) = (%q, _) want %q", tc.weights, gotItem, tc.wantItem)
			}
		})
	}
}

func TestWeightedRandomSampleInDef(t *testing.T) {
	tests := []struct {
		name      string
		weights   map[string]float32
		wantOneOf []string
		wantErr   bool
	}{
		{
			name:      "TwoWeights",
			weights:   map[string]float32{"a": 0.5, "b": 0.0, "c": 3.0},
			wantOneOf: []string{"a", "c"},
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotItem, err := weightedRandomSample(tc.weights)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("weightedRandomSample(%v) = (_, error: %v), want err? %t", tc.weights, err, tc.wantErr)
			}
			for _, i := range tc.wantOneOf {
				if i == gotItem {
					return
				}
			}
			t.Errorf("weightedRandomSample(%v) = (%q, _) want any item of %v", tc.weights, gotItem, tc.wantOneOf)
		})
	}
}
