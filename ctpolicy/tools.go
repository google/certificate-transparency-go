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
	"fmt"
	"math/rand"
)

// weightedRandomSample picks an item from the weighted set and returns it.
// Follows weight distribution provided and ignores items whose weight is 0.
// If it's not possible (e.g. all items have 0 weights), returns error.
// Expects all weights to be non-negative, otherwise returns error.
func weightedRandomSample(weights map[string]float32) (string, error) {
	var sum float32
	for itemName, w := range weights {
		if w < 0.0 {
			return "", fmt.Errorf("weightedRandomSample got negative weight %v for item %v, all weights should be non-negative", w, itemName)
		}
		sum += w
	}
	r := rand.Float32() * sum
	for itemName, w := range weights {
		if w == 0.0 {
			continue
		}
		r -= w
		if r < 0.0 {
			return itemName, nil
		}
	}
	return "", fmt.Errorf("weightedRandomSample couldn't pick any item")
}
