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
	// LogListRefreshInterval is interval between consecutive reads of Log-list.
	LogListRefreshInterval = time.Hour * 24 * 7

	// HttpClientTimeout timeout for Log list reader http client.
	httpClientTimeout = 10 * time.Second
)

// LogListEvent wraps result of single Log list refresh. Only one field
// expected to be set.
type LogListEvent struct {
	// Ll is new version of Log list. Emitted when update observed.
	Ll *loglist.LogList
	// Err is error on reading/parsing Log-list source.
	Err error
}

// LogListRefresher regularly reads Log-list and emits notifications when updates/errors
// observed.
type LogListRefresher struct {
	// Events is an output channel emitting events of Log-list updates/errors.
	Events chan *LogListEvent

	// updateMu guards single update process.
	updateMu sync.RWMutex
	ll       *loglist.LogList
	path     string
}

// NewLogListRefresher creates and inits a LogListRefresher instance.
// The LogListRefresher will asynchronously try to read LogList using path provided.
// Call Run() to (re)start regular reads and listen to Events channel.
func NewLogListRefresher(llPath string) *LogListRefresher {
	return &LogListRefresher{
		path:   llPath,
		Events: make(chan *LogListEvent),
	}
}

// sendEventIfAny redirects non-empty events to the output channel.
func (llr *LogListRefresher) sendEventIfAny() {
	if evt := llr.read(); evt != nil {
		llr.Events <- evt
	}
}

// Run starts regular Log list refreshes.
func (llr *LogListRefresher) Run(ctx context.Context) {
	ticker := time.NewTicker(LogListRefreshInterval)
	defer ticker.Stop()

	llr.sendEventIfAny()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			llr.sendEventIfAny()
		}
	}
}

// Check runs singular Log list refresh.
func (llr *LogListRefresher) Check() {
	go llr.sendEventIfAny()
}

// read runs single Log list refresh and forms LogListEvent instance containing
// info on update/error observed.
func (llr *LogListRefresher) read() *LogListEvent {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()
	client := &http.Client{Timeout: httpClientTimeout}
	llData, err := x509util.ReadFileOrURL(llr.path, client)

	var evt LogListEvent
	if err != nil {
		evt.Err = fmt.Errorf("failed to read %q: %v", llr.path, err)
		return &evt
	}
	ll, err := loglist.NewFromJSON(llData)
	if err != nil {
		evt.Err = fmt.Errorf("failed to parse %q: %v", llr.path, err)
		return &evt
	}
	if reflect.DeepEqual(ll, llr.ll) {
		return nil
	}
	// Event of LogList update.
	evt.Ll = ll
	llr.ll = ll
	return &evt
}
