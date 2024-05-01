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

package ctfe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"
)

func TestIssuanceChainServiceAddAndGet(t *testing.T) {
	tests := []struct {
		chain []byte
	}{
		{readTestData(t, "leaf00.chain")},
		{readTestData(t, "leaf01.chain")},
		{readTestData(t, "leaf02.chain")},
		{nil},
	}

	ctx := context.Background()
	storage := newFakeIssuanceChainStorage()
	cache := newFakeIssuanceChainCache()
	issuanceChainService := NewIssuanceChainService(storage, cache)

	for _, test := range tests {
		hash, err := issuanceChainService.Add(ctx, test.chain)
		if err != nil {
			t.Errorf("IssuanceChainService.Add(): %v", err)
		}

		got, err := issuanceChainService.GetByHash(ctx, hash)
		if err != nil {
			t.Errorf("IssuanceChainService.GetByHash(): %v", err)
		}

		if !bytes.Equal(got, test.chain) {
			t.Errorf("GetByHash = %v, want %v", got, test.chain)
		}
	}
}

func TestIssuanceChainServiceChainHashLen(t *testing.T) {
	want := sha256.Size
	tests := []struct {
		chain []byte
	}{
		{readTestData(t, "leaf00.chain")},
		{readTestData(t, "leaf01.chain")},
		{readTestData(t, "leaf02.chain")},
		{nil},
	}

	issuanceChainService := NewIssuanceChainService(nil, nil)

	for _, test := range tests {
		got := len(issuanceChainService.ChainHash(test.chain))
		if got != want {
			t.Errorf("len(ChainHash(%v)) = %d, want %d", test.chain, got, want)
		}
	}
}

func readTestData(t *testing.T, filename string) []byte {
	t.Helper()

	data, err := os.ReadFile("../testdata/" + filename)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

type fakeIssuanceChainStorage struct {
	chains map[string][]byte
}

func newFakeIssuanceChainStorage() fakeIssuanceChainStorage {
	return fakeIssuanceChainStorage{
		chains: make(map[string][]byte),
	}
}

func (s fakeIssuanceChainStorage) FindByKey(_ context.Context, key []byte) ([]byte, error) {
	return s.chains[string(key)], nil
}

func (s fakeIssuanceChainStorage) Add(_ context.Context, key []byte, chain []byte) error {
	s.chains[string(key)] = chain
	return nil
}

type fakeIssuanceChainCache struct {
	chains map[string][]byte
}

func newFakeIssuanceChainCache() fakeIssuanceChainCache {
	return fakeIssuanceChainCache{
		chains: make(map[string][]byte),
	}
}

func (c fakeIssuanceChainCache) Get(_ context.Context, key []byte) ([]byte, error) {
	return c.chains[string(key)], nil
}

func (c fakeIssuanceChainCache) Set(_ context.Context, key []byte, chain []byte) error {
	c.chains[string(key)] = chain
	return nil
}
