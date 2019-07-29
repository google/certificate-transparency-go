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
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/go-cmp/cmp"
)

// createTempFile creates a file in the system's temp directory and writes data to it.
// It returns the name of the file.
func createTempFile(data string) (string, error) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func ExampleLogListRefresher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f, err := createTempFile(`{"operators": [{"name":"Google"}]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)

	// Refresh log list periodically so it stays up-to-date.
	// Not necessary for this example, but appropriate for long-running systems.
	llChan := make(chan *LogListData)
	errChan := make(chan error)
	go schedule.Every(ctx, time.Hour, func(ctx context.Context) {
		if ll, err := llr.Refresh(); err != nil {
			errChan <- err
		} else {
			llChan <- ll
		}
	})

	select {
	case ll := <-llChan:
		fmt.Printf("# Log Operators: %d\n", len(ll.List.Operators))
	case err := <-errChan:
		panic(err)
	case <-ctx.Done():
		panic("Context expired")
	}
	// Output:
	// # Log Operators: 1
}

func TestNewLogListRefresherNoFile(t *testing.T) {
	const wantErrSubstr = "failed to read"
	llr := NewLogListRefresher("nofile.json")
	if _, err := llr.Refresh(); !strings.Contains(err.Error(), wantErrSubstr) {
		t.Errorf("llr.Refresh() = (_, %v), want err containing %q", err, wantErrSubstr)
	}
}

type fakeTransport struct {
	called bool
}

func (ft *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.called = true
	return nil, fmt.Errorf("fakeTransport got called")
}

func TestNewCustomLogListRefresher(t *testing.T) {
	transport := fakeTransport{}
	client := &http.Client{Transport: &transport, Timeout: time.Second}

	llr := NewCustomLogListRefresher(client, "https://loglist.net/")
	if _, err := llr.Refresh(); err == nil {
		t.Errorf("Expected llr.Refresh() to return error using fakeTransport, got none")
	}
	if transport.called != true {
		t.Errorf("NewCustomLogListRefresher initialized with fakeTransport didn't call it on Refresh()")
	}
}

func TestNewLogListRefresher(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		wantLl    *loglist2.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:   "SuccessfulRead",
			ll:     `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl: &loglist2.LogList{Operators: []*loglist2.Operator{{Name: "Google"}}},
		},
		{
			name:      "CannotParseInput",
			ll:        `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer os.Remove(f)

			beforeRefresh := time.Now()
			llr := NewLogListRefresher(f)
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if (ll == nil) != (tc.wantLl == nil) {
				t.Fatalf("llr.Refresh() = (%v, _), expected value? %t", ll, tc.wantLl != nil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(ll.List, tc.wantLl); diff != "" {
				t.Errorf("llr.Refresh() LogList: diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.ll)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}

func TestNewLogListRefresherUpdate(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		llNext    string
		wantLl    *loglist2.LogList
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
			wantLl:    &loglist2.LogList{Operators: []*loglist2.Operator{{Name: "GoogleOps"}}},
			errRegexp: nil,
		},
		{
			name:      "CannotParseInput",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer os.Remove(f)

			llr := NewLogListRefresher(f)
			if _, err := llr.Refresh(); err != nil {
				t.Fatalf("llr.Refresh() = (_, %v), want (_, nil)", err)
			}

			// Simulate Log list update.
			if err := ioutil.WriteFile(f, []byte(tc.llNext), 0755); err != nil {
				t.Fatalf("ioutil.WriteFile(%q, %q) = %q, want nil", f, tc.llNext, err)
			}

			beforeRefresh := time.Now()
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if llNil, wantNil := ll == nil, tc.wantLl == nil; llNil != wantNil {
				t.Fatalf("llr.Refresh() = (%v, _), expected nil? %t", ll, wantNil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(tc.wantLl, ll.List); diff != "" {
				t.Errorf("llr.Refresh(): diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.llNext)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}
