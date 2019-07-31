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

// Package ctpolicy contains structs describing CT policy requirements and corresponding logic.
package ctpolicy

import (
	"fmt"
	"sync"

	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/x509"
)

const (
	// BaseName is name for the group covering all logs.
	BaseName = "All-logs"
)

// LogGroupInfo holds information on a single group of logs specified by Policy.
type LogGroupInfo struct {
	Name          string
	LogURLs       map[string]bool    // set of members
	MinInclusions int                // Required number of submissions.
	IsBase        bool               // True only for Log-group covering all logs.
	LogWeights    map[string]float32 // weights used for submission, default weight is 1
	wMu           sync.RWMutex       // guards weights
}

func (group *LogGroupInfo) setMinInclusions(i int) error {
	if i < 0 {
		return fmt.Errorf("cannot assign negative minimal inclusions number")
	}
	// Assign given number even if it's bigger than group size.
	group.MinInclusions = i
	if i > len(group.LogURLs) {
		return fmt.Errorf("trying to assign %d minimal inclusion number while only %d logs are part of group %q", i, len(group.LogURLs), group.Name)
	}
	return nil
}

func (group *LogGroupInfo) populate(ll *loglist2.LogList, included func(op *loglist2.Operator) bool) {
	group.LogURLs = make(map[string]bool)
	group.LogWeights = make(map[string]float32)
	for _, op := range ll.Operators {
		if included(op) {
			for _, l := range op.Logs {
				group.LogURLs[l.URL] = true
				group.LogWeights[l.URL] = 1.0
			}
		}
	}
}

// satisfyMinimalInclusion returns whether number of positive weights is
// bigger or equal to minimal inclusion number.
func (group *LogGroupInfo) satisfyMinimalInclusion(weights map[string]float32) bool {
	nonZeroNum := 0
	for logURL, w := range weights {
		if group.LogURLs[logURL] && w > 0.0 {
			nonZeroNum++
			if nonZeroNum >= group.MinInclusions {
				return true
			}
		}
	}
	return false
}

// SetLogWeights applies suggested weights to the Log-group. Does not reset
// weights and returns error when there are not enough positive weights
// provided to reach minimal inclusion number.
func (group *LogGroupInfo) SetLogWeights(weights map[string]float32) error {
	for logURL, w := range weights {
		if w < 0.0 {
			return fmt.Errorf("trying to assign negative weight %v to Log %q", w, logURL)
		}
	}
	if !group.satisfyMinimalInclusion(weights) {
		return fmt.Errorf("trying to assign weights %v resulting into unability to reach minimal inclusion number %d", weights, group.MinInclusions)
	}
	group.wMu.Lock()
	defer group.wMu.Unlock()
	// All group weights initially reset to 0.0
	for logURL := range group.LogURLs {
		group.LogWeights[logURL] = 0.0
	}
	for logURL, w := range weights {
		if group.LogURLs[logURL] {
			group.LogWeights[logURL] = w
		}
	}
	return nil
}

// SetLogWeight tries setting the weight for a single Log of the Log-group.
// Does not reset the weight and returns error if weight is non-positive and
// its setting will result innto unability to reach minimal inclusion number.
func (group *LogGroupInfo) SetLogWeight(logURL string, w float32) error {
	if !group.LogURLs[logURL] {
		return fmt.Errorf("trying to assign weight to Log %q not belonging to the group", logURL)
	}
	if w < 0.0 {
		return fmt.Errorf("trying to assign negative weight %v to Log %q", w, logURL)
	}
	newWeights := make(map[string]float32)
	for l, wt := range group.LogWeights {
		newWeights[l] = wt
	}
	newWeights[logURL] = w
	if !group.satisfyMinimalInclusion(newWeights) {
		return fmt.Errorf("assigning weight %v to Log %q will result into unability to reach minimal inclusion number %d", w, logURL, group.MinInclusions)
	}
	group.wMu.Lock()
	defer group.wMu.Unlock()
	group.LogWeights = newWeights
	return nil
}

// GetSubmissionSession produces list of log-URLs of the Log-group.
// Order of the list is weighted random defined by Log-weights within the group
func (group *LogGroupInfo) GetSubmissionSession() []string {
	if len(group.LogURLs) == 0 {
		return make([]string, 0)
	}
	session := make([]string, 0)
	// modelling weighted random with exclusion

	unProcessedWeights := make(map[string]float32)
	for logURL, w := range group.LogWeights {
		unProcessedWeights[logURL] = w
	}

	group.wMu.RLock()
	defer group.wMu.RUnlock()
	for range group.LogURLs {
		sampleLog, err := weightedRandomSample(unProcessedWeights)
		if err != nil {
			// session still valid, not covering all Logs
			return session
		}
		session = append(session, sampleLog)
		delete(unProcessedWeights, sampleLog)
	}
	return session
}

// LogPolicyData contains info on log-partition and submission requirements
// for a single cert. Key always matches value Name field.
type LogPolicyData map[string]*LogGroupInfo

// TotalLogs returns number of logs within set of Log-groups.
// Taking possible intersection into account.
func (groups LogPolicyData) TotalLogs() int {
	unifiedLogs := make(map[string]bool)
	for _, g := range groups {
		if g.IsBase {
			return len(g.LogURLs)
		}
		for l := range g.LogURLs {
			unifiedLogs[l] = true
		}
	}
	return len(unifiedLogs)
}

// CTPolicy interface describes requirements determined for logs in terms of
// per-group-submit.
type CTPolicy interface {
	// LogsByGroup provides info on Log-grouping. Returns an error if it's not
	// possible to satisfy the policy with the provided loglist.
	LogsByGroup(cert *x509.Certificate, approved *loglist2.LogList) (LogPolicyData, error)
	Name() string
}

// BaseGroupFor creates and propagates all-log group.
func BaseGroupFor(approved *loglist2.LogList, incCount int) (*LogGroupInfo, error) {
	baseGroup := LogGroupInfo{Name: BaseName, IsBase: true}
	baseGroup.populate(approved, func(op *loglist2.Operator) bool { return true })
	err := baseGroup.setMinInclusions(incCount)
	return &baseGroup, err
}

// lifetimeInMonths calculates and returns cert lifetime expressed in months
// flooring incomplete month.
func lifetimeInMonths(cert *x509.Certificate) int {
	startYear, startMonth, startDay := cert.NotBefore.Date()
	endYear, endMonth, endDay := cert.NotAfter.Date()
	lifetimeInMonths := (int(endYear)-int(startYear))*12 + (int(endMonth) - int(startMonth))
	if endDay < startDay {
		// partial month
		lifetimeInMonths--
	}
	return lifetimeInMonths
}

// GroupSet is set of Log-group names.
type GroupSet map[string]bool

// GroupByLogs reverses match-map between Logs and Groups.
// Returns map from log-URLs to set of Group-names that contain the log.
func GroupByLogs(lg LogPolicyData) map[string]GroupSet {
	result := make(map[string]GroupSet)
	for groupname, g := range lg {
		for logURL := range g.LogURLs {
			if _, seen := result[logURL]; !seen {
				result[logURL] = make(GroupSet)
			}
			result[logURL][groupname] = true
		}
	}
	return result
}
