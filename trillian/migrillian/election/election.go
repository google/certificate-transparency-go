// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package election provides master election tools, and interfaces for plugging
// in a custom underlying mechanism.
// TODO(pavelkalinnikov): Migrate this package to Trillian.
package election

import "context"

// Election controls an instance's participation in master election process.
type Election interface {
	// Await blocks until the instance captures mastership. Returns the "master
	// context" which remains active until the instance stops being the master,
	// or the passed in context is canceled. Returns an error if capturing fails,
	// or the passed in context is canceled before mastership is captured.
	Await(ctx context.Context) (context.Context, error)

	// Resign cancels the master context and releases mastership for this
	// instance. The instance can be elected again using Await.
	//
	// Master context cancelation is guaranteed, but the returned error can
	// indicate that resigning has failed. In the latter case it might be helpful
	// to retry, the call is idempotent.
	Resign(ctx context.Context) error

	// Close cancels the master context, permanently stops participating in
	// election, and releases the resources. As a best effort, it might also try
	// to explicitly Resign so that other instances can overtake mastership
	// faster. No other method should be called after Close.
	Close(ctx context.Context) error
}

// Factory encapsulates the creation of an Election instance for a treeID.
type Factory interface {
	NewElection(ctx context.Context, treeID int64) (Election, error)
}
