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

// Package noop defines the IssuanceChainCache type, which implements IssuanceChainCache interface with Get and Set operations.
package noop

import "context"

type IssuanceChainCache struct{}

func (c *IssuanceChainCache) Get(_ context.Context, key []byte) ([]byte, error) {
	return nil, nil
}

func (c *IssuanceChainCache) Set(_ context.Context, key []byte, chain []byte) error {
	return nil
}
