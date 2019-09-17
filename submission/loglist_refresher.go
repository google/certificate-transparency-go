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

	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	// HttpClientTimeout timeout for Log list reader http client.
	httpClientTimeout = 10 * time.Second
)

// LogListData wraps info on external LogList, keeping its JSON source and time
// of download.
type LogListData struct {
	JSON         []byte
	List         *loglist2.LogList
	DownloadTime time.Time
}

// LogListRefresher is interface for Log List updates watcher.
type LogListRefresher interface {
	Refresh() (*LogListData, error)
	LastJSON() []byte
	Source() string
}

// logListRefresherImpl regularly reads Log-list and emits notifications when
// updates/errors observed. Implements LogListRefresher interface.
type logListRefresherImpl struct {
	// updateMu limits LogListRefresherImpl to a single Refresh() at a time.
	updateMu sync.RWMutex
	lastJSON []byte
	path     string
	client   *http.Client
}

// NewCustomLogListRefresher creates and inits a LogListRefresherImpl instance.
func NewCustomLogListRefresher(client *http.Client, llPath string) LogListRefresher {
	return &logListRefresherImpl{
		path:   llPath,
		client: client,
	}
}

// NewLogListRefresher creates and inits a LogListRefresherImpl instance using
// default http.Client
func NewLogListRefresher(llPath string) LogListRefresher {
	return NewCustomLogListRefresher(&http.Client{Timeout: httpClientTimeout}, llPath)
}

// Refresh fetches the log list and returns its source, formed LogList and
// timestamp if source has changed compared to previous Refresh.
func (llr *logListRefresherImpl) Refresh() (*LogListData, error) {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()

	t := time.Now()
	json, err := x509util.ReadFileOrURL(llr.path, llr.client)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", llr.path, err)
	}

	if bytes.Equal(json, llr.lastJSON) {
		return nil, nil
	}

	ll, err := loglist2.NewFromJSON(json)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", llr.path, err)
	}
	llr.lastJSON = json
	return &LogListData{JSON: json, List: ll, DownloadTime: t}, nil
}

// LastJSON returns last version of Log list in JSON.
func (llr *logListRefresherImpl) LastJSON() []byte {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()
	if llr.lastJSON == nil {
		return []byte{}
	}
	return llr.lastJSON
}

// Source exposes internal Log list path.
func (llr *logListRefresherImpl) Source() string {
	return llr.path
}
