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
	"os"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/testdata"
)

func TestNoLLRefresher(t *testing.T) {
	llm := NewLogListManager(nil)
	_, err := llm.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("llm.RefreshLogList() on nil LogListRefresher expected to get error, got none")
	}
}

func TestNoLLRefresherAfterRun(t *testing.T) {
	llm := NewLogListManager(nil)
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
	llm := NewLogListManager(llr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	llm.Run(ctx, 3*time.Second)
	select {
	case <-llm.LLUpdates:
		return
	case err := <-llm.Errors:
		t.Errorf("llm.Run() returned error %q while expected none", err)
	case <-ctx.Done():
		t.Errorf("llm.Run() on stub LogListRefresher expected to emit update, got none")
	}
}
