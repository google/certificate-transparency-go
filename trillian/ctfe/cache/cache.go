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
	// Get returns the issuance chain associated with the provided hash.
	Get(ctx context.Context, key []byte) ([]byte, error)

	// Set inserts the key-value pair of issuance chain.
	Set(ctx context.Context, key []byte, chain []byte) error
}
