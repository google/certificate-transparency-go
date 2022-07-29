// Copyright 2016 Google LLC. All Rights Reserved.
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

package ratelimiter

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"k8s.io/klog/v2"
)

var testlimits = []int{1, 10, 50, 100, 1000}

func TestRateLimiterSingleThreaded(t *testing.T) {
	for i, limit := range testlimits {
		t.Run(fmt.Sprintf("%d ops/s", limit), func(t *testing.T) {
			i, limit := i, limit
			t.Parallel()
			l := NewLimiter(limit)

			numOps := 3 * limit
			start := time.Now()
			// Need to call the limiter one extra time to ensure that the throughput
			// calculation is correct (because e.g. at 1 qps you can do 3 calls in
			// 2+epsilon seconds)
			for i := 0; i < numOps+1; i++ {
				l.Wait()
			}
			ds := float64(time.Since(start)) / float64(time.Second)
			qps := float64(numOps) / ds
			if qps > float64(limit)*1.01 {
				t.Errorf("#%d: Too many operations per second. Expected ~%d, got %f", i, limit, qps)
			}
			klog.Infof("#%d: Expected ~%d, got %f", i, limit, qps)
		})
	}
}

func TestRateLimiterGoroutines(t *testing.T) {
	for i, limit := range testlimits {
		t.Run(fmt.Sprintf("%d ops/s", limit), func(t *testing.T) {
			i, limit := i, limit
			t.Parallel()
			l := NewLimiter(limit)

			numOps := 3 * limit
			var wg sync.WaitGroup
			start := time.Now()
			// Need to call the limiter one extra time to ensure that the throughput
			// calculation is correct (because e.g. at 1 qps you can do 3 calls in
			// 2+epsilon seconds)
			for i := 0; i < numOps+1; i++ {
				wg.Add(1)
				go func() {
					l.Wait()
					wg.Done()
				}()
			}
			wg.Wait()
			ds := float64(time.Since(start)) / float64(time.Second)
			qps := float64(numOps) / ds
			if qps > float64(limit)*1.01 {
				t.Errorf("#%d: Too many operations per second. Expected ~%d, got %f", i, limit, qps)
			}
			klog.Infof("#%d: Expected ~%d, got %f", i, limit, qps)
		})
	}
}
