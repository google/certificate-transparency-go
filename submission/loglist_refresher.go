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
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	// LoglistRefreshInterval is interval between consecutive external reads of Log-list.
	loglistRefreshInterval = time.Hour * 24 * 7
)

// LogListEvent wraps result of sinle Log list refresh.
type LogListEvent struct {
	Ll  *loglist.LogList
	Err error
}

// LoglistRefresher regularly reads Log-list and emits notifications when updates/errors
// observed.
type LoglistRefresher struct {
	mu   sync.RWMutex
	ll   *loglist.LogList
	path string

	Events chan *LogListEvent

	// Guards ticker.
	tmu    sync.Mutex
	ticker *time.Ticker
}

// NewLoglistRefresher creates and inits a LoglistRefresher instance.
// The LoglistRefresher will asynchronously try to read Loglist using path provided.
// Call Run() to (re)start regular reads and listen to Events channel.
func NewLoglistRefresher(llPath string) *LoglistRefresher {
	var llr LoglistRefresher
	llr.path = llPath
	llr.Events = make(chan *LogListEvent)
	return &llr
}

// sendEventIfAny redirects non-empty events to the output channel.
func (llr *LoglistRefresher) sendEventIfAny() {
	evt := llr.read()
	if evt != nil {
		llr.Events <- evt
	}
}

// Run starts regular Log list refreshes.
func (llr *LoglistRefresher) Run(ctx context.Context) {
	llr.tmu.Lock()
	if llr.ticker != nil {
		// Re-start the ticker.
		llr.ticker = time.NewTicker(loglistRefreshInterval)
		llr.tmu.Unlock()
		llr.sendEventIfAny()
		return
	}

	llr.ticker = time.NewTicker(loglistRefreshInterval)
	llr.tmu.Unlock()

	llr.sendEventIfAny()

	for {
		select {
		case <-ctx.Done():
			llr.tmu.Lock()
			defer llr.tmu.Unlock()
			if llr.ticker != nil {
				llr.ticker.Stop()
				llr.ticker = nil
			}
			return
		case <-llr.ticker.C:
			llr.sendEventIfAny()
		}
	}
}

// read runs single Log list refresh and forms LogListEvent instance containing
// info on update/error observed.
func (llr *LoglistRefresher) read() *LogListEvent {
	client := &http.Client{Timeout: time.Second * 10}
	llData, err := x509util.ReadFileOrURL(llr.path, client)

	var evt LogListEvent
	if err != nil {
		evt.Err = fmt.Errorf("failed to read log list: %v", err)
		return &evt
	}
	ll, err := loglist.NewFromJSON(llData)
	if err != nil {
		evt.Err = fmt.Errorf("failed to parse log list: %v", err)
		return &evt
	}
	llr.mu.Lock()
	defer llr.mu.Unlock()
	if reflect.DeepEqual(ll, llr.ll) {
		fmt.Printf("some\n")
		return nil
	}
	// Event of Loglist update.
	evt.Ll = ll
	llr.ll = ll
	return &evt
}
