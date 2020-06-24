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

// Package watcher holds tools for loglist-files versioning and updates propagation.
package watcher

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// Diff regularly check data at path provided, notifies if changes detected.
type Diff struct {
	latest []byte

	synced []byte
	diffs  []diffmatchpatch.Diff
	// mu guards all data-fields: latest, synced and diffs.
	mu sync.Mutex

	// Exactly one of url/filepath fields is specified.
	url      string
	filepath string

	checkInterval time.Duration

	events chan<- DiffEvent
}

// DiffEvent refelects diff/error detection.
type DiffEvent struct {
	Diffs []diffmatchpatch.Diff
	Err   error
}

// NewDiff is factory for Diff.
func NewDiff(ctx context.Context, path string, isPathURL bool, checkInterval time.Duration, events chan<- DiffEvent) *Diff {
	var d Diff
	if isPathURL {
		d.url = path
	} else {
		d.filepath = path
	}
	d.checkInterval = checkInterval
	d.events = events

	d.init(ctx)
	return &d
}

func (d *Diff) init(ctx context.Context) {
	d.checkUpdate()
	go schedule.Every(ctx, d.checkInterval, func(ctx context.Context) {
		d.checkUpdate()
	})
}

func (d *Diff) checkUpdate() {
	var path string
	if len(d.url) > 0 {
		path = d.url
	} else {
		path = d.filepath
	}
	llData, err := x509util.ReadFileOrURL(path, &http.Client{Timeout: time.Second * 10})
	if err != nil {
		d.events <- DiffEvent{Err: err}
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.latest = llData
	// Compare data as strings
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(string(d.synced), string(d.latest), false)
	d.diffs = diffs
	if len(diffs) > 0 && d.events != nil {
		d.events <- DiffEvent{Diffs: d.diffs}
	}
}

func (d *Diff) sync() { // nolint:unused
	d.mu.Lock()
	d.synced = d.latest
	d.diffs = []diffmatchpatch.Diff{}
	d.mu.Unlock()
}

// GetSyncedData provides acces to Diff data.
func (d *Diff) GetSyncedData() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.synced
}
