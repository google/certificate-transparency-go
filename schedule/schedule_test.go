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

package schedule

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvery(t *testing.T) {
	for _, test := range []struct {
		name           string
		period         time.Duration
		timeout        time.Duration
		wantExecutions uint32
	}{
		{
			name:           "0 runs",
			period:         100 * time.Millisecond,
			timeout:        0,
			wantExecutions: 0,
		},
		{
			name:           "1 run",
			period:         100 * time.Millisecond,
			timeout:        50 * time.Millisecond,
			wantExecutions: 1,
		},
		{
			name:           "3 runs 100ms apart",
			period:         100 * time.Millisecond,
			timeout:        250 * time.Millisecond,
			wantExecutions: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			var counter uint32

			Every(ctx, test.period, func(ctx context.Context) {
				atomic.AddUint32(&counter, 1)
			})

			if got, want := atomic.LoadUint32(&counter), test.wantExecutions; got != want {
				t.Fatalf("Every(%v, f): executed f %d times, want %d times", test.period, got, want)
			}
		})
	}
}
