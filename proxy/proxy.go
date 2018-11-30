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

package watcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
	
	"github.com/google/certificate-transparency-go/ctpolicy"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/sergi/go-diff/diffmatchpatch"
	"golang.org/x/net/context/ctxhttp"
)

const (

	port = "localhost:8080"

	ShowBaseStatePath = "/base-state"

	CheckInterval = time.Duration(24) * time.Hour
)

type protectedData struct {
	data []byte
	refreshTimepoint time.Time
	mu sync.Mutex
}

func (pd *protectedData) updateTimepoint() {
	pd.mu.Lock()
	pd.refreshTimepoint = time.Now()
	pd.mu.Unlock()
}

func (pd *protectedData) updateData(refresh []byte) {
	pd.mu.Lock()
	pd.data = refresh
	pd.refreshTimepoint = time.Now()
	pd.mu.Unlock()
}



func main() {
	http.HandleFunc("/", updateHandler)

	log.Fatal(http.ListenAndServe(port, nil))
}


// watcher tracks 2 source-points treating them as base- and branch-versions of the same data. It runs comparison-syncs when updates detected.

type watcher struct {
	baseWatcher *diffWatcher
	branchWatcher *diffWatcher
	
	// URL for log-list page.
	trueLogListPath string

	// URL/filepath to branched version.
	branchLogListPath string

	baseEvents <-chan DiffEvent
	branchEvents <-chan DiffEvent

	inSync bool
}


func NewWatcher(baseLogListPath string, branchLogListPath string) (*watcher, err) {
	var w watcher
	w.baseEvents := make(chan DiffEvent)
	w.branchEvents:= make(chan DiffEvent)

	w.baseWatcher := NewDiffWatcher(baseLogListPath, true, CheckInterval, baseEvents)
	w.branchWatcher := NewDiffWatcher(branchLogListPath, true, CheckInterval, branchEvents)


	go func() {
		for true {
			d := <- w.baseEvents
			if (d.Diffs != nil) {
				inSync = false
				w.IncomingUpdate()
			}
			if (d.Err != nil) {

			}
		}
	}()
}


func (w *watcher) IncomingUpdate() {
	inSync = false

}

func (s *server) (ll *loglist.LogList) {
	
	// run diff
	if empty {
		s.latestBase.updateTimepoint();
		return
	}

	// Notify active LogList needs sync.
}

func (s *server) init() {
	// get latestDownload
	// set-up latestBase
	// get consumerData
}

func (s *server) resync() {
	// Show 2 diffs.
	dmp := diffmatchpatch.New()
	// baseDiff represents diff between downloaded data and data used as base during last sync. Result of unsynced updates.
	baseDiff := dmp.DiffMain(s.latestBase, s.latestDownload, false)

	// deriveDiff is diff between base and consumer data; result of manual changes.
	deriveDiff := dmp.DiffMain(s.latestBase, s.consumerData, false)

	patches := dmp.PatchMake(s.latestDownload, deriveDiff)
	autoSyncData, patchResults := dmp.PatchApply(patches, s.consumerData)

	autoSyncDiff := dmp.DiffMain(s.consumerData, autosyncDiff)

	for __, r := patchResults {
		if !r {
			// autoSync is incomplete; notify
		}
	}

	// Show autoSyncData, wait for confirmation.

	// Try parsing result until it's valid LogList-diff.


}

func isParsableLogList(data []byte) bool {
	ll loglist.LogList
	return json.Unmarshal(body, &ll) == nil
}

