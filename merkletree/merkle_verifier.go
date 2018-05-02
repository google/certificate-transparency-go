// Copyright 2016 Google Inc. All Rights Reserved.
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

package merkletree

import (
	"github.com/google/trillian/merkle"
)

// TODO(pavelkalinnikov): Get rid of these and use Trillian code directly.
type RootMismatchError = merkle.RootMismatchError
type MerkleVerifier = merkle.LogVerifier

// NewMerkleVerifier returns a new MerkleVerifier for a tree based on the
// passed in hasher.
func NewMerkleVerifier(h HasherFunc) MerkleVerifier {
	hasher := NewTreeHasher(h)
	return merkle.NewLogVerifier(hasher)
}
