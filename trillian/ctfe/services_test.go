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
	"sync"
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
	storage := &fakeIssuanceChainStorage{}
	cache := &fakeIssuanceChainCache{}
	issuanceChainService := newIssuanceChainService(storage, cache)

	for _, test := range tests {
		hash, err := issuanceChainService.add(ctx, test.chain)
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

func TestIssuanceChainHashLen(t *testing.T) {
	want := sha256.Size
	tests := []struct {
		chain []byte
	}{
		{readTestData(t, "leaf00.chain")},
		{readTestData(t, "leaf01.chain")},
		{readTestData(t, "leaf02.chain")},
		{nil},
	}

	for _, test := range tests {
		got := len(issuanceChainHash(test.chain))
		if got != want {
			t.Errorf("len(issuanceChainHash(%v)) = %d, want %d", test.chain, got, want)
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
	chains sync.Map
}

func (s *fakeIssuanceChainStorage) FindByKey(_ context.Context, key []byte) ([]byte, error) {
	val, _ := s.chains.Load(string(key))
	chain, _ := val.([]byte)
	return chain, nil
}

func (s *fakeIssuanceChainStorage) Add(_ context.Context, key []byte, chain []byte) error {
	s.chains.Store(string(key), chain)
	return nil
}

type fakeIssuanceChainCache struct {
	chains sync.Map
}

func (c *fakeIssuanceChainCache) Get(_ context.Context, key []byte) ([]byte, error) {
	val, _ := c.chains.Load(string(key))
	chain, _ := val.([]byte)
	return chain, nil
}

func (c *fakeIssuanceChainCache) Set(_ context.Context, key []byte, chain []byte) error {
	c.chains.Store(string(key), chain)
	return nil
}
