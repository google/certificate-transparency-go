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

package storage

import (
	"context"
)

// IssuanceChainStorage is an interface which allows CTFE binaries to use different storage implementations for issuance chains.
type IssuanceChainStorage interface {
	// FindAll returns all key-value pairs of issuance chains.
	FindAll(ctx context.Context) (map[string][]byte, error)

	// FindByKey returns the issuance chain associated with the provided key.
	FindByKey(ctx context.Context, key string) ([]byte, error)

	// Add inserts the key-value pair of issuance chain.
	Add(ctx context.Context, key string, chain []byte) error
}
