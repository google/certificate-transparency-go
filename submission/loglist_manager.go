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

	"github.com/google/certificate-transparency-go/schedule"
)

// LogListManager runs loglist updates and keeps two latest versions of Log
// list.
type LogListManager struct {
	Errors    chan error
	LLUpdates chan LogListData

	llRefreshInterval time.Duration

	llr        LogListRefresher
	latestLL   *LogListData
	previousLL *LogListData
	mu         sync.Mutex // guards latestLL and previousLL
}

// NewLogListManager creates and inits a LogListManager instance.
func NewLogListManager(llr LogListRefresher) *LogListManager {
	return &LogListManager{
		Errors:    make(chan error, 1),
		LLUpdates: make(chan LogListData, 1),
		llr:       llr,
	}
}

// Run starts regular LogList checks and associated versions archiving.
// Emits errors and Loglist-updates into its corresponding channels, expected
// to have readers listening.
func (llm *LogListManager) Run(ctx context.Context, llRefresh time.Duration) {
	llm.llRefreshInterval = llRefresh
	go schedule.Every(ctx, llm.llRefreshInterval, llm.refreshLogListAndNotify)
}

// refreshLogListAndNotify runs single Log-list refresh and propagates data and
// errors to corresponding channels
func (llm *LogListManager) refreshLogListAndNotify(ctx context.Context) {
	if lld, err := llm.RefreshLogList(ctx); err != nil {
		llm.Errors <- err
	} else if lld != nil {
		llm.LLUpdates <- llm.ProduceClientLogList()
	}
}

// GetTwoLatestLogLists returns last version of Log list and a previous one.
func (llm *LogListManager) GetTwoLatestLogLists() (*LogListData, *LogListData) {
	llm.mu.Lock()
	defer llm.mu.Unlock()
	return llm.latestLL, llm.previousLL
}

// RefreshLogList reads Log List one time and runs updates if necessary.
func (llm *LogListManager) RefreshLogList(ctx context.Context) (*LogListData, error) {
	if llm.llr == nil {
		return nil, fmt.Errorf("the LogListManager has no LogListRefresher")
	}
	ll, err := llm.llr.Refresh()
	if err != nil {
		return nil, err
	}
	if ll == nil {
		// No updates
		return nil, nil
	}
	llm.mu.Lock()
	defer llm.mu.Unlock()
	llm.previousLL = llm.latestLL
	llm.latestLL = ll
	return llm.latestLL, nil
}

// ProduceClientLogList applies client filtration on Log list.
func (llm *LogListManager) ProduceClientLogList() LogListData {
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
