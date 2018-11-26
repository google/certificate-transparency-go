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

package races

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctpolicy"
)

const (
	// PostBatchInterval is duration between parallel batch call and subsequent requests to Logs within group.
	PostBatchInterval = time.Second
)

type safeStringSet struct {
	entries map[string]bool
	mu      sync.Mutex
}

// add includes the entry in the set, returns whether the entry wasn't included before.
func (gList *safeStringSet) add(logURL string) bool {
	gList.mu.Lock()
	defer gList.mu.Unlock()
	if gList.entries[logURL] {
		return false
	}
	gList.entries[logURL] = true
	return true
}

func (gList *safeStringSet) has(logURL string) bool {
	gList.mu.Lock()
	defer gList.mu.Unlock()
	return gList.entries[logURL]
}

func (gList *safeStringSet) sumFor(URLs map[string]bool) int {
	var matches int
	gList.mu.Lock()
	defer gList.mu.Unlock()
	for url := range URLs {
		if gList.entries[url] {
			matches++
		}
	}
	return matches
}

// submissionResult holds outcome from a single-log submission.
type submissionResult struct {
	logURL string
	sct    *ct.SignedCertificateTimestamp
	err    error
}

// postInterval calculates duration for consequent call. For first parallelStart calls duration is 0, while every next one gets additional dur interval.
func postInterval(idx int, parallelStart int, dur time.Duration) time.Duration {
	if idx < parallelStart {
		return time.Duration(0)
	}
	return time.Duration(idx+1-parallelStart) * dur
}

// Submitter is interface wrapping Log-request-response cycle and any processing.
type Submitter interface {
	SubmitToLog(ctx context.Context, logURL string, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
}

func groupRace(ctx context.Context, chain []ct.ASN1Cert, group *ctpolicy.LogGroupInfo, parallelStart int,
	results chan<- submissionResult, requested *safeStringSet, receivedSCTFrom *safeStringSet, submitter Submitter) {
	groupURLs := make([]string, 0, len(group.LogURLs))
	for logURL := range group.LogURLs {
		groupURLs = append(groupURLs, logURL)
	}
	// Randomize the order in which we send requests to the logs in a group
	// so we maximize the distribution of logs we get SCTs from.
	for i, urlNum := range rand.Perm(len(groupURLs)) {
		go func(i int, logURL string) {
			time.Sleep(postInterval(i, parallelStart, PostBatchInterval))
			if ctx.Err() != nil {
				return
			}
			if firstRequested := requested.add(logURL); !firstRequested {
				return
			}
			if receivedSCTFrom.sumFor(group.LogURLs) >= group.MinInclusions {
				return
			}
			sct, err := submitter.SubmitToLog(ctx, logURL, chain)
			// verify SCT
			results <- submissionResult{logURL: logURL, sct: sct, err: err}
		}(i, groupURLs[urlNum])
	}
}

func parallelNums(groups ctpolicy.LogPolicyData) map[string]int {
	nums := make(map[string]int)
	var subsetSum int
	for _, g := range groups {
		if !g.IsBase {
			nums[g.Name] = g.MinInclusions
			subsetSum += g.MinInclusions
		}
	}
	nums[ctpolicy.BaseName] -= subsetSum
	return nums
}

// AssignedSCT represents SCT with logURL of log-producer.
type AssignedSCT struct {
	LogURL string
	Sct    *ct.SignedCertificateTimestamp
}

func groupsComplete(groups ctpolicy.LogPolicyData, receivedSCTFrom *safeStringSet) bool {
	for _, g := range groups {
		var withinGroup int
		for logURL := range g.LogURLs {
			if receivedSCTFrom.has(logURL) {
				withinGroup++
			}
		}
		if withinGroup < g.MinInclusions {
			return false
		}
	}
	return true
}

func completenessError(groups ctpolicy.LogPolicyData, receivedSCTFrom *safeStringSet) error {
	if !groupsComplete(groups, receivedSCTFrom) {
		return errors.New("Not all log-groups collected required number of SCTs")
	}
	return nil
}

// GetSCTs picks required number of Logs according to policy-group logic and collects SCTs from them. Emits all collected SCTs even when any error produced.
func GetSCTs(ctx context.Context, submitter Submitter, chain []ct.ASN1Cert, groups ctpolicy.LogPolicyData) ([]*AssignedSCT, error) {
	logsNumber := groups.TotalLogs()
	results := make(chan submissionResult, logsNumber)
	requested := safeStringSet{entries: make(map[string]bool)}
	receivedSCTFrom := safeStringSet{entries: make(map[string]bool)}
	parallelNums := parallelNums(groups)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, g := range groups {
		go groupRace(subCtx, chain, g, parallelNums[g.Name], results, &requested, &receivedSCTFrom, submitter)
	}

	var collectedSCTs []*AssignedSCT
	// Terminates upon either all logs available are requested or required number of SCTs is collected or upon context timeout.
	for i := 0; i < logsNumber; i++ {
		select {
		case <-ctx.Done():
			err := completenessError(groups, &receivedSCTFrom)
			return collectedSCTs, err
		case res := <-results:
			if res.sct != nil {
				collectedSCTs = append(collectedSCTs, &AssignedSCT{LogURL: res.logURL, Sct: res.sct})
				receivedSCTFrom.add(res.logURL)
				if groupsComplete(groups, &receivedSCTFrom) {
					return collectedSCTs, nil
				}
			}
		}
	}
	err := completenessError(groups, &receivedSCTFrom)
	return collectedSCTs, err
}
