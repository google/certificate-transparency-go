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

// Package cache defines the IssuanceChainCache type, which allows different cache implementation with Get and Set operations.
package cache

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe/cache/lru"
	"github.com/google/certificate-transparency-go/trillian/ctfe/cache/noop"
)

var (
	cacheType = flag.String("cache_type", "noop", "Supported cache type: noop, lru (Default: noop)")
	size      = flag.Int("cache_size", 0, "Size parameter set to 0 makes cache of unlimited size")
	ttl       = flag.Duration("cache_ttl", 0*time.Second, "Providing 0 TTL turns expiring off")
)

// IssuanceChainCache is an interface which allows CTFE binaries to use different cache implementations for issuance chains.
type IssuanceChainCache interface {
	// Get returns the issuance chain associated with the provided hash.
	Get(ctx context.Context, key []byte) ([]byte, error)

	// Set inserts the key-value pair of issuance chain.
	Set(ctx context.Context, key []byte, chain []byte) error
}

// NewIssuanceChainCache returns nil for noop type or lru.IssuanceChainCache for lru cache type.
func NewIssuanceChainCache(_ context.Context) (IssuanceChainCache, error) {
	switch *cacheType {
	case "noop":
		return &noop.IssuanceChainCache{}, nil
	case "lru":
		if *size < 0 {
			return nil, errors.New("invalid cache_size flag")
		}
		if *ttl < 0*time.Second {
			return nil, errors.New("invalid cache_ttl flag")
		}
		return lru.NewIssuanceChainCache(lru.CacheOption{Size: *size, TTL: *ttl}), nil
	}

	return nil, errors.New("invalid cache_type flag")
}
