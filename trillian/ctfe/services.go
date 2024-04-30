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
	"context"
	"crypto/sha256"

	"github.com/google/certificate-transparency-go/trillian/ctfe/cache"
	"github.com/google/certificate-transparency-go/trillian/ctfe/storage"
	"k8s.io/klog/v2"
)

type IssuanceChainService struct {
	storage storage.IssuanceChainStorage
	cache   cache.IssuanceChainCache
}

func NewIssuanceChainService(ctx context.Context, s storage.IssuanceChainStorage, c cache.IssuanceChainCache) *IssuanceChainService {
	service := &IssuanceChainService{
		storage: s,
		cache:   c,
	}

	return service
}

// GetByHash returns the issuance chain with hash as the input.
func (s *IssuanceChainService) GetByHash(ctx context.Context, hash []byte) ([]byte, error) {
	// Return if found in cache.
	chain, err := s.cache.Get(ctx, hash)
	if chain != nil || err != nil {
		return chain, err
	}

	// Find in storage if cache miss.
	chain, err = s.storage.FindByKey(ctx, hash)
	if err != nil {
		return nil, err
	}

	// If there is any error from cache set, do not return the error because
	// the chain is still available for read.
	if err := s.cache.Set(ctx, hash, chain); err != nil {
		klog.Errorf("failed to set hash and chain into cache: %v", err)
	}

	return chain, nil
}

// Add adds the issuance chain into the storage and cache and returns the hash
// of the chain.
func (s *IssuanceChainService) Add(ctx context.Context, chain []byte) ([]byte, error) {
	hash := s.ChainHash(chain)

	err := s.storage.Add(ctx, hash, chain)
	if err != nil {
		return nil, err
	}

	// If there is any error from cache set, do not return the error because
	// the chain is already stored.
	if err := s.cache.Set(ctx, hash, chain); err != nil {
		klog.Errorf("failed to set hash and chain into cache: %v", err)
	}

	return hash, nil
}

// ChainHash returns the SHA-256 hash of the chain.
func (s *IssuanceChainService) ChainHash(chain []byte) []byte {
	checksum := sha256.Sum256(chain)
	return checksum[:]
}