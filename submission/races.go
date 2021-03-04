// Copyright 2018 Google LLC. All Rights Reserved.
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
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctpolicy"
)

const (
	// PostBatchInterval is duration between parallel batch call and subsequent
	// requests to Logs within group.
	// TODO(Mercurrent): optimize to avoid excessive requests.
	PostBatchInterval = time.Second
)

// Submitter is interface wrapping Log-request-response cycle and any processing.
type Submitter interface {
	SubmitToLog(ctx context.Context, logURL string, chain []ct.ASN1Cert, asPreChain bool) (*ct.SignedCertificateTimestamp, error)
}

// submissionResult holds outcome of a single-log submission.
type submissionResult struct {
	sct *ct.SignedCertificateTimestamp
	err error
}

type groupState struct {
	Name    string
	Success bool
}

// safeSubmissionState is a submission state-machine for set of Log-groups.
// When some group is complete cancels all requests that are not needed by any
// group.
type safeSubmissionState struct {
	mu          sync.Mutex
	logToGroups map[string]ctpolicy.GroupSet
	groupNeeds  map[string]int

	results map[string]*submissionResult
	cancels map[string]context.CancelFunc
}

func newSafeSubmissionState(groups ctpolicy.LogPolicyData) *safeSubmissionState {
	var s safeSubmissionState
	s.logToGroups = ctpolicy.GroupByLogs(groups)
	s.groupNeeds = make(map[string]int)
	for _, g := range groups {
		s.groupNeeds[g.Name] = g.MinInclusions
	}
	s.results = make(map[string]*submissionResult)
	s.cancels = make(map[string]context.CancelFunc)
	return &s
}

// request includes empty submissionResult in the set, returns whether
// the entry is requested for the first time.
func (sub *safeSubmissionState) request(logURL string, cancel context.CancelFunc) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.results[logURL] != nil {
		// Already requested.
		return false
	}
	sub.results[logURL] = &submissionResult{}
	isAwaited := false
	for g := range sub.logToGroups[logURL] {
		if sub.groupNeeds[g] > 0 {
			isAwaited = true
			break
		}
	}
	if !isAwaited {
		// No groups expecting result from this Log.
		return false
	}
	sub.cancels[logURL] = cancel
	return true
}

// setResult processes SCT-result. Writes it down if it is error or awaited-SCT.
// Re-calculates group-completion and cancels any running but
// not-awaited-anymore Log-requests.
func (sub *safeSubmissionState) setResult(logURL string, sct *ct.SignedCertificateTimestamp, err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sct == nil {
		sub.results[logURL] = &submissionResult{sct: sct, err: err}
		return
	}
	// If at least one group needs that SCT, result is set. Otherwise dumped.
	for groupName := range sub.logToGroups[logURL] {
		// Ignore the base group (All-logs) here to check separately.
		if groupName == ctpolicy.BaseName {
			continue
		}
		if sub.groupNeeds[groupName] > 0 {
			sub.results[logURL] = &submissionResult{sct: sct, err: err}
		}
		sub.groupNeeds[groupName]--
	}

	// Check the base group (All-logs) only
	if sub.logToGroups[logURL][ctpolicy.BaseName] {
		if sub.results[logURL].sct != nil {
			// It is already processed in a non-base group, so we can reduce the groupNeeds for the base group as well.
			sub.groupNeeds[ctpolicy.BaseName]--
		} else if sub.groupNeeds[ctpolicy.BaseName] > 0 {
			minInclusionsForOtherGroup := 0
			for g, cnt := range sub.groupNeeds {
				if g != ctpolicy.BaseName && cnt > 0 {
					minInclusionsForOtherGroup += cnt
				}
			}
			// Set the result only if the base group still needs SCTs more than total counts
			// of minimum inclusions for other groups.
			if sub.groupNeeds[ctpolicy.BaseName] > minInclusionsForOtherGroup {
				sub.results[logURL] = &submissionResult{sct: sct, err: err}
				sub.groupNeeds[ctpolicy.BaseName]--
			}
		}
	}

	// Cancel any pending Log-requests for which there're no more awaiting
	// Log-groups.
	for logURL, groupSet := range sub.logToGroups {
		isAwaited := false
		for g := range groupSet {
			if sub.groupNeeds[g] > 0 {
				isAwaited = true
				break
			}
		}
		if !isAwaited && sub.cancels[logURL] != nil {
			sub.cancels[logURL]()
			sub.cancels[logURL] = nil
		}
	}
}

// groupComplete returns true iff the specified group has all the SCTs it needs.
func (sub *safeSubmissionState) groupComplete(groupName string) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	needs, ok := sub.groupNeeds[groupName]
	if !ok {
		return true
	}
	return needs <= 0
}

func (sub *safeSubmissionState) collectSCTs() []*AssignedSCT {
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

// postInterval calculates duration for consequent call.
// For first parallelStart calls duration is 0, while every next one gets
// additional dur interval.
func postInterval(idx int, parallelStart int, dur time.Duration) time.Duration {
	if idx < parallelStart {
		return time.Duration(0)
	}
	return time.Duration(idx+1-parallelStart) * dur
}

// groupRace shuffles logs within the group, submits avoiding
// duplicate-requests and collects responses.
func groupRace(ctx context.Context, chain []ct.ASN1Cert, asPreChain bool,
	group *ctpolicy.LogGroupInfo, parallelStart int,
	state *safeSubmissionState, submitter Submitter) groupState {
	// Randomize the order in which we send requests to the logs in a group
	// so we maximize the distribution of logs we get SCTs from.
	session := group.GetSubmissionSession()
	type count struct{}
	counter := make(chan count, len(session))

	countCall := func() {
		counter <- count{}
	}

	for i, logURL := range session {
		subCtx, cancel := context.WithCancel(ctx)
		go func(i int, logURL string) {
			defer countCall()
			timeoutchan := time.After(postInterval(i, parallelStart, PostBatchInterval))

			select {
			case <-subCtx.Done():
				return
			case <-timeoutchan:
			}
			if state.groupComplete(group.Name) {
				cancel()
				return
			}
			if firstRequested := state.request(logURL, cancel); !firstRequested {
				return
			}
			sct, err := submitter.SubmitToLog(subCtx, logURL, chain, asPreChain)
			// TODO(Mercurrent): verify SCT
			state.setResult(logURL, sct, err)
		}(i, logURL)
	}
	// Wait until either all logs within session are processed or context is
	// cancelled.
	for range session {
		select {
		case <-ctx.Done():
			return groupState{Name: group.Name, Success: state.groupComplete(group.Name)}
		case <-counter:
			if state.groupComplete(group.Name) {
				return groupState{Name: group.Name, Success: true}
			}
		}
	}
	return groupState{Name: group.Name, Success: state.groupComplete(group.Name)}
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
		return fmt.Errorf("log-group(s) %s didn't receive enough SCTs", strings.Join(failedGroups, ", "))
	}
	return nil
}

// GetSCTs picks required number of Logs according to policy-group logic and
// collects SCTs from them.
// Emits all collected SCTs even when any error produced.
func GetSCTs(ctx context.Context, submitter Submitter, chain []ct.ASN1Cert, asPreChain bool, groups ctpolicy.LogPolicyData) ([]*AssignedSCT, error) {
	groupComplete := make(map[string]bool)
	for _, g := range groups {
		groupComplete[g.Name] = false
	}

	parallelNums := parallelNums(groups)
	// channel listening to group-completion (failure) events from each single group-race.
	groupEvents := make(chan groupState, len(groups))
	submissions := newSafeSubmissionState(groups)
	for _, g := range groups {
		go func(g *ctpolicy.LogGroupInfo) {
			groupEvents <- groupRace(ctx, chain, asPreChain, g, parallelNums[g.Name], submissions, submitter)
		}(g)
	}

	// Terminates upon either all logs available are requested or required
	// number of SCTs is collected or upon context timeout.
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
