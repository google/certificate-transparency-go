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
	"math/rand"

	"github.com/google/certificate-transparency-go/loglist"
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

func (group *LogGroupInfo) populate(ll *loglist.LogList, included func(log *loglist.Log) bool) {
	group.LogURLs = make(map[string]bool)
	group.LogWeights = make(map[string]float32)
	for _, l := range ll.Logs {
		if included(&l) {
			group.LogURLs[l.URL] = true
			group.LogWeights[l.URL] = 1.0
		}
	}
}

// resetLogWeights applies suggested weights to the Log-group. Does not reset
// weights and returns error when not enough to reach minimal inclusion number
// positive weights provided.
func (group *LogGroupInfo) ResetLogWeights(weights map[string]float32) error {
	groupWeights := make(map[string]float32, len(group.LogURLs))
	for logURL := range group.LogURLs {
		groupWeights[logURL] = 1.0
	}
	nonZeroNum := len(group.LogURLs)
	for logURL, w := range weights {
		if group.LogURLs[logURL] {
			groupWeights[logURL] = w
			if w <= 0 {
				nonZeroNum--
			}
		}
	}
	if nonZeroNum < group.MinInclusions {
		return fmt.Errorf("trying to assign weights %v resulting into unability to reach minimal inclusion number %d", weights, group.MinInclusions)
	}
	group.LogWeights = groupWeights
	return nil
}

// setLogWeight tries setting weights for a single Log of the Log-group.
// Does not reset the weight and returns error if weight is non-positive and
// its setting will result innto unability to reach minimal inclusion number.
func (group *LogGroupInfo) SetLogWeight(logURL string, w float32) error {
	if !group.LogURLs[logURL] {
		return nil
	}
	if w > 0.0 || group.LogWeights[logURL] <= 0.0 {
		group.LogWeights[logURL] = w
		return nil
	}
	var nonZeroNum int
	for _, w := range group.LogWeights {
		if w > 0 {
			nonZeroNum++
		}
	}
	if nonZeroNum <= group.MinInclusions {
		return fmt.Errorf("setting weight %f for log %q would result into unability to reach minimum inclusion number %d", w, logURL, group.MinInclusions)
	}
	group.LogWeights[logURL] = w
	return nil
}

// getSubmissionSession produces list of log-URLs of the Log-group.
// Order of the list is weighted random defined by Log-weights within the group
func (group *LogGroupInfo) GetSubmissionSession() []string {
	if len(group.LogURLs) == 0 {
		return make([]string, 0)
	}
	session := make([]string, 0)
	// modelling weighted random with exclusion

	var sum float32
	for _, w := range group.LogWeights {
		sum += w
	}
	processedURLs := make(map[string]bool)
	for logURL := range group.LogURLs {
		processedURLs[logURL] = false
	}

	for i := 0; i < len(group.LogURLs); i++ {
		if sum <= 0.0 {
			break
		}
		r := rand.Float32() * sum
		for logURL, w := range group.LogWeights {
			if processedURLs[logURL] || w <= 0.0 {
				continue
			}
			r -= w
			if r < 0.0 {
				session = append(session, logURL)
				processedURLs[logURL] = true
				sum -= w
			}
		}

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
	// Provides info on Log-grouping. Returns an error if loglist provided is
	// not sufficient to satisfy policy.
	// The data output is formed even when error returned.
	LogsByGroup(cert *x509.Certificate, approved *loglist.LogList) (LogPolicyData, error)
	Name() string
}

// BaseGroupFor creates and propagates all-log group.
func BaseGroupFor(approved *loglist.LogList, incCount int) (LogGroupInfo, error) {
	baseGroup := LogGroupInfo{Name: BaseName, IsBase: true}
	baseGroup.populate(approved, func(log *loglist.Log) bool { return true })
	err := baseGroup.setMinInclusions(incCount)
	return baseGroup, err
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
