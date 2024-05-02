// Copyright 2024 Google LLC
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

package lru

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"
)

func TestLRUIssuanceChainCache(t *testing.T) {
	cacheSize := 3

	tests := setupTestData(t,
		"leaf00.chain",
		"leaf01.chain",
		"leaf02.chain",
	)

	cache := NewIssuanceChainCache(CacheOption{Size: cacheSize})

	for key, val := range tests {
		if err := cache.Set(context.Background(), []byte(key), val); err != nil {
			t.Errorf("cache.Set: %v", err)
		}
	}

	for key, want := range tests {
		got, err := cache.Get(context.Background(), []byte(key))
		if err != nil {
			t.Errorf("cache.Get: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}

func setupTestData(t *testing.T, filenames ...string) map[string][]byte {
	t.Helper()

	data := make(map[string][]byte, len(filenames))

	for _, filename := range filenames {
		val, err := os.ReadFile("../../../testdata/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		key := sha256.Sum256(val)
		data[string(key[:])] = val
	}

	return data
}
