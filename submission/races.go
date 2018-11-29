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
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctpolicy"
)

const (
	// PostBatchInterval is duration between parallel batch call and subsequent requests to Logs within group.
	// TODO(Mercurrent): optimize to avoid excessive requests.
	PostBatchInterval = time.Second
)

// submissionState holds outcome of a single-log submission.
type submissionResult struct {
	sct *ct.SignedCertificateTimestamp
	err error
}

// safeSubmissionSet guards submission states for set of Logs.
type safeSubmissionSet struct {
	results map[string]*submissionResult
	mu      sync.Mutex
}

// request includes empty submissionResult in the set, returns whether the entry wasn't requested (added) before.
func (sub *safeSubmissionSet) request(logURL string) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.results[logURL] != nil {
		return false
	}
	sub.results[logURL] = &submissionResult{}
	return true
}

func (sub *safeSubmissionSet) has(logURL string) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.results[logURL] != nil
}

func (sub *safeSubmissionSet) sumSCTsFor(URLs map[string]bool) int {
	var matches int
	sub.mu.Lock()
	defer sub.mu.Unlock()
	for url := range URLs {
		if sub.results[url] != nil && sub.results[url].sct != nil {
			matches++
		}
	}
	return matches
}

func (sub *safeSubmissionSet) setResult(logURL string, sct *ct.SignedCertificateTimestamp, err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	sub.results[logURL] = &submissionResult{sct: sct, err: err}
}

func (sub *safeSubmissionSet) collectSCTs() []*AssignedSCT {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	scts := []*AssignedSCT{}
	for logURL, r := range sub.results {
		if r != nil && r.sct != nil {
			scts = append(scts, &AssignedSCT{LogURL: logURL, SCT: r.sct})
		}
	}
	return scts
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

type groupState struct {
	Name    string
	Success bool
}

// groupRace shuffles logs within the group, submits avoiding duplicate-requests and collects responses. Upon (not)reaching required number of SCTs returns.
func groupRace(ctx context.Context, chain []ct.ASN1Cert, group *ctpolicy.LogGroupInfo, parallelStart int,
	state *safeSubmissionSet, submitter Submitter) groupState {
	groupURLs := make([]string, 0, len(group.LogURLs))
	for logURL := range group.LogURLs {
		groupURLs = append(groupURLs, logURL)
	}

	type count struct{}
	counter := make(chan count, len(groupURLs))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Randomize the order in which we send requests to the logs in a group
	// so we maximize the distribution of logs we get SCTs from.
	for i, urlNum := range rand.Perm(len(groupURLs)) {
		go func(i int, logURL string) {
			timeoutchan := time.After(postInterval(i, parallelStart, PostBatchInterval))
			select {
			case <-subCtx.Done():
				counter <- count{}
				return
			case <-timeoutchan:
			}
			if state.sumSCTsFor(group.LogURLs) >= group.MinInclusions {
				cancel()
				counter <- count{}
				return
			}
			if firstRequested := state.request(logURL); !firstRequested {
				counter <- count{}
				return
			}
			// Relies on parent context. Even when group is complete, this SCT should be returned as requests for this Log have already been blocked for all other groups.
			sct, err := submitter.SubmitToLog(ctx, logURL, chain)
			// TODO(Mercurrent): verify SCT
			state.setResult(logURL, sct, err)
			counter <- count{}
		}(i, groupURLs[urlNum])
	}
	// Wait until either all logs within groups are processed or context is cancelled.
	for i := 0; i < len(groupURLs); i++ {
		select {
		case <-ctx.Done():
			break
		case <-counter:
			if state.sumSCTsFor(group.LogURLs) >= group.MinInclusions {
				cancel()
			}
		}
	}
	return groupState{Name: group.Name, Success: state.sumSCTsFor(group.LogURLs) >= group.MinInclusions}
}

func parallelNums(groups ctpolicy.LogPolicyData) map[string]int {
	nums := make(map[string]int)
	var subsetSum int
	for _, g := range groups {
		nums[g.Name] = g.MinInclusions
		if !g.IsBase {
			subsetSum += g.MinInclusions
		}
	}
	if _, hasBase := nums[ctpolicy.BaseName]; hasBase {
		if nums[ctpolicy.BaseName] >= subsetSum {
			nums[ctpolicy.BaseName] -= subsetSum
		} else {
			nums[ctpolicy.BaseName] = 0
		}
	}
	return nums
}

// AssignedSCT represents SCT with logURL of log-producer.
type AssignedSCT struct {
	LogURL string
	SCT    *ct.SignedCertificateTimestamp
}

func completenessError(groupComplete map[string]bool) error {
	failedGroups := []string{}
	for name, success := range groupComplete {
		if !success {
			failedGroups = append(failedGroups, name)
		}
	}
	if len(failedGroups) > 0 {
		return errors.New("Log-group(s) " + strings.Join(failedGroups, ", ") + "didn't receive enough SCTs.")
	}
	return nil
}

// GetSCTs picks required number of Logs according to policy-group logic and collects SCTs from them.
// Emits all collected SCTs even when any error produced.
func GetSCTs(ctx context.Context, submitter Submitter, chain []ct.ASN1Cert, groups ctpolicy.LogPolicyData) ([]*AssignedSCT, error) {
	parallelNums := parallelNums(groups)
	submissions := safeSubmissionSet{results: make(map[string]*submissionResult)}
	// channel listening to group-completion (failure) events
	groupEvents := make(chan groupState, len(groups))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, g := range groups {
		go func(g *ctpolicy.LogGroupInfo) {
			groupEvents <- groupRace(subCtx, chain, g, parallelNums[g.Name], &submissions, submitter)
		}(g)
	}

	// A group name being present in the map indicates that group has
	// completed processing, and the bool value indicates whether it
	// completed successfully.
	groupComplete := make(map[string]bool)
	// Terminates upon either all logs available are requested or required number of SCTs is collected or upon context timeout.
	for i := 0; i < len(groups); i++ {
		select {
		case <-ctx.Done():
			return submissions.collectSCTs(), completenessError(groupComplete)
		case g := <-groupEvents:
			groupComplete[g.Name] = g.Success
		}
	}
	return submissions.collectSCTs(), completenessError(groupComplete)
}
