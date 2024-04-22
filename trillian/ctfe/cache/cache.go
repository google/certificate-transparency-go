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

import "context"

// IssuanceChainCache is an interface which allows CTFE binaries to use different cache implementations for issuance chains.
type IssuanceChainCache interface {
	// IsLazyLoading returns whether lazy loading is enabled for the cache. This value comes from the the log configuration.
	// When IsLazyLoading is true, the issuance chain is inserted into the cache when there is a cache miss.
	// When IsLazyLoading is false, the issuance chains are expected to be preloaded into the cache during initialization.
	IsLazyLoading() bool

	// Get returns the issuance chain associated with the provided hash.
	Get(ctx context.Context, hash string) ([]byte, error)

	// Set inserts the key-value pair of issuance chain.
	Set(ctx context.Context, hash string, chain []byte) error
}
