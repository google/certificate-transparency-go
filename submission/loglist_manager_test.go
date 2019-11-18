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
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/trillian/monitoring"
)

func TestNoLLRefresher(t *testing.T) {
	llm := NewLogListManager(nil, nil)
	_, err := llm.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("llm.RefreshLogList() on nil LogListRefresher expected to get error, got none")
	}
}

func TestNoLLRefresherAfterRun(t *testing.T) {
	llm := NewLogListManager(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	llm.Run(ctx, 3*time.Second)
	select {
	case <-llm.Errors:
		return
	case <-ctx.Done():
		t.Errorf("llm.Run() on nil LogListRefresher expected to emit error, got none")
	}
}

func TestFirstRefresh(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList, err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	llm := NewLogListManager(llr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	llm.Run(ctx, 3*time.Second)
	select {
	case <-llm.LLUpdates:
		return
	case err := <-llm.Errors:
		t.Errorf("llm.Run() emitted error %q while expected none", err)
	case <-ctx.Done():
		t.Errorf("llm.Run() on stub LogListRefresher expected to emit update, got none")
	}
}

func TestSecondRefresh(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList, err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	llm := NewLogListManager(llr, monitoring.InertMetricFactory{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	halfCtx, halfCancel := context.WithTimeout(context.Background(), time.Second)
	defer halfCancel()

	llm.Run(ctx, 300*time.Millisecond)
	readFirst := false
First:
	for {
		select {
		case <-llm.LLUpdates:
			if !readFirst {
				readFirst = true
			} else {
				t.Errorf("llm.Run() emitted Log-list update when no updates happened")
			}
		case err := <-llm.Errors:
			t.Errorf("llm.Run() remitted error %q while expected none", err)
		case <-halfCtx.Done():
			if !readFirst {
				t.Errorf("llm.Run() didn't emit any Log-list updates on init. Expected one")
			}
			break First
		}
	}

	sampleLogListUpdate := strings.Replace(testdata.SampleLogList, "ct.googleapis.com/racketeer/", "ct.googleapis.com/racketeer/v2/", 1)
	if err := ioutil.WriteFile(f, []byte(sampleLogListUpdate), 0644); err != nil {
		t.Fatalf("unable to update Log-list data file: %q", err)
	}
	select {
	case <-llm.LLUpdates:
		return
	case err := <-llm.Errors:
		t.Errorf("llm.Run() emitted error %q while expected none", err)
	case <-ctx.Done():
		t.Errorf("llm.Run() on stub LogListRefresher expected to emit update, got none")
	}
}
