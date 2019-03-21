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
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/go-cmp/cmp"
)

func createTempFile(t *testing.T, name string, data []byte) *os.File {
	t.Helper()
	f, err := ioutil.TempFile("", name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatalf("Unable to write into testing file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Unable to close testing file: %v", err)
	}
	return f
}

func rewriteDataFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := ioutil.WriteFile(name, data, 0755); err != nil {
		t.Fatalf("unable to update file %q: %v", name, err)
	}
}

func compareEvents(t *testing.T, gotEvt *LogListEvent, wantLl *loglist.LogList, errRegexp *regexp.Regexp) {
	if gotEvt == nil {
		if wantLl != nil || errRegexp != nil {
			t.Errorf("Got no LogList event while wanted (%v; %v)", wantLl, errRegexp)
		}
		return
	}

	if diff := cmp.Diff(wantLl, gotEvt.Ll); diff != "" {
		t.Errorf("LogList update event is not expected %s", diff)
	}
	if errRegexp != nil {
		if gotEvt.Err == nil || !errRegexp.MatchString(gotEvt.Err.Error()) {
			t.Errorf("Got error event %q did not match wanted substring %q", gotEvt.Err, errRegexp)
		}
	} else if gotEvt.Err != nil {
		t.Errorf("Got error event %q while none expected", gotEvt.Err)
	}
}

func TestNewLogListRefresherNoFile(t *testing.T) {
	llr := NewLogListRefresher("nofile.json")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go llr.Run(ctx)
	evt := <-llr.Events
	if !strings.Contains(evt.Err.Error(), "failed to read") {
		t.Errorf("Expected getting error event on reading non-existent file, got %s", evt.Err)
	}
}

func TestNewLogListRefresher(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		wantLl    *loglist.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:   "SuccessfulRead",
			ll:     `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl: &loglist.LogList{Operators: []loglist.Operator{{ID: 0, Name: "Google"}}},
		},
		{
			name:      "CannotParseInput",
			ll:        `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := createTempFile(t, "loglist.json", []byte(tc.ll))
			defer os.Remove(f.Name())

			llr := NewLogListRefresher(f.Name())
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			go llr.Run(ctx)

			gotEvt := <-llr.Events
			compareEvents(t, gotEvt, tc.wantLl, tc.errRegexp)
		})
	}
}

func TestNewLogListRefresherUpdate(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		llNext    string
		wantLl    *loglist.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:      "NoUpdate",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl:    nil,
			errRegexp: nil,
		},
		{
			name:      "LogListUpdated",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"GoogleOps"}]}`,
			wantLl:    &loglist.LogList{Operators: []loglist.Operator{{ID: 0, Name: "GoogleOps"}}},
			errRegexp: nil,
		},
		{
			name:      "CannotReadInput",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := createTempFile(t, "loglist.json", []byte(tc.ll))
			defer os.Remove(f.Name())

			llr := NewLogListRefresher(f.Name())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go llr.Run(ctx)
			<-llr.Events

			// Simulate Log list update.
			rewriteDataFile(t, f.Name(), []byte(tc.llNext))

			llr.Check()
			// Wait for event if any.
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer waitCancel()

			select {
			case gotEvt := <-llr.Events:
				compareEvents(t, gotEvt, tc.wantLl, tc.errRegexp)
			case <-waitCtx.Done():
				compareEvents(t, nil, tc.wantLl, tc.errRegexp)
			}
		})
	}
}
