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
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	// HttpClientTimeout timeout for Log list reader http client.
	httpClientTimeout = 10 * time.Second
)

// LogListRefresher regularly reads Log-list and emits notifications when updates/errors
// observed.
type LogListRefresher struct {
	// updateMu limits LogListRefresher to a single Refresh() at a time.
	updateMu sync.RWMutex
	lastJSON []byte
	path     string
}

// NewLogListRefresher creates and inits a LogListRefresher instance.
// The LogListRefresher will asynchronously try to read LogList using path provided.
// Call Run() to (re)start regular reads and listen to Events channel.
func NewLogListRefresher(llPath string) *LogListRefresher {
	return &LogListRefresher{
		path: llPath,
	}
}

// Refresh fetches the log list and returns it if it has changed.
func (llr *LogListRefresher) Refresh() (*loglist.LogList, error) {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()
	client := &http.Client{Timeout: httpClientTimeout}

	json, err := x509util.ReadFileOrURL(llr.path, client)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", llr.path, err)
	}

	if bytes.Equal(json, llr.lastJSON) {
		return nil, nil
	}

	ll, err := loglist.NewFromJSON(json)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", llr.path, err)
	}
	llr.lastJSON = json
	return ll, nil
}
