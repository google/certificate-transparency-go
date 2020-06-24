// Copyright 2018 Google LLC. All Rights Reserved.
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

package core

import (
	"context"
	"sync"
)

// RunMigration migrates data from a number of CT logs to Trillian. Each log's
// migration is coordinated by the corresponding Controller. This function
// terminates when all Controllers are done (possibly with an error, or as a
// result of canceling the passed in context).
func RunMigration(ctx context.Context, ctrls []*Controller) {
	var wg sync.WaitGroup
	for _, ctrl := range ctrls {
		wg.Add(1)
		go func(ctrl *Controller) {
			defer wg.Done()
			ctrl.RunWhenMasterWithRestarts(ctx)
		}(ctrl)
	}
	wg.Wait()
}
