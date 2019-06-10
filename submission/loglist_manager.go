// Copyright 2019 Google Inc. All Rights Reserved.
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

package submission

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/schedule"
)

// LoglistManager runs loglist updates and keeps two latest versions of Log
// list.
type LogListManager struct {
	Errors    chan error
	LLUpdates chan loglist.LogList
	initOnce  sync.Once

	llRefreshInterval time.Duration

	llr        LogListRefresher
	latestLL   *loglist.LogList
	previousLL *loglist.LogList
	updateMu   sync.Mutex
}

// NewLogListManager creates and inits a LogListManager instance.
func NewLogListManager(llr LogListRefresher) *LogListManager {
	var llm LogListManager
	llm.Errors = make(chan error, 1)
	llm.LLUpdates = make(chan loglist.LogList, 1)
	llm.llr = llr
	return &llm
}

// Run starts regular LogList checks and associated versions archiving.
func (llm *LogListManager) Run(ctx context.Context, llRefresh time.Duration) {
	runBody := func() {
		llm.llRefreshInterval = llRefresh
		go schedule.Every(ctx, llm.llRefreshInterval, func(ctx context.Context) {
			if ll, err := llm.RefreshLogList(ctx); err != nil {
				llm.Errors <- err
			} else if ll != nil {
				llm.LLUpdates <- llm.ProduceClientLogList()
			}
		})
	}
	llm.initOnce.Do(runBody)
}

// LatestLogList returns last version of Log list.
func (llm *LogListManager) LatestLogList() *loglist.LogList {
	llm.updateMu.Lock()
	defer llm.updateMu.Unlock()
	return llm.latestLL
}

// PreviousLogList returns the version of Log List that was before latest and
// time of its retrieval.
func (llm *LogListManager) PreviousLogList() *loglist.LogList {
	llm.updateMu.Lock()
	defer llm.updateMu.Unlock()
	return llm.previousLL
}

// RefreshLogList reads Log List one time and runs updates if necessary.
func (llm *LogListManager) RefreshLogList(ctx context.Context) (*loglist.LogList, error) {
	if llm.llr == nil {
		return nil, fmt.Errorf("Log list manager has no log-list watcher to refresh Log List")
	}
	ll, err := llm.llr.Refresh()
	if err != nil {
		return nil, err
	}
	llm.updateMu.Lock()
	defer llm.updateMu.Unlock()
	if ll == nil {
		// No updates
		return nil, nil
	}
	llm.previousLL = llm.latestLL
	llm.latestLL = ll
	return llm.latestLL, nil
}

// Applies client filtration on Log list.
func (llm *LogListManager) ProduceClientLogList() loglist.LogList {
	// TODO(Mercurrent): Add filtration
	clientLL := *(llm.latestLL)
	return clientLL
}

// Source exposes internal Log list path.
func (llm *LogListManager) Source() string {
	return llm.llr.Source()
}

// LastJSON returns last version of Log list in JSON.
func (llm *LogListManager) LastJSON() []byte {
	return llm.llr.LastJSON()
}
