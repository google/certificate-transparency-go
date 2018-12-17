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
	LogURLs       map[string]bool // set of members
	MinInclusions int             // Required number of submissions.
	IsBase        bool            // True only for Log-group covering all logs.
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
	for _, l := range ll.Logs {
		if included(&l) {
			group.LogURLs[l.URL] = true
		}
	}
}

// LogPolicyData contains info on log-partition and submission requirements for a single cert. Key always matches value Name field.
type LogPolicyData map[string]*LogGroupInfo

// CTPolicy interface describes requirements determined for logs in terms of per-group-submit.
type CTPolicy interface {
	// Provides info on Log-grouping. Returns an error if loglist provided is not sufficient to satisfy policy. The data output is formed even when error returned.
	LogsByGroup(cert *x509.Certificate, approved *loglist.LogList) (LogPolicyData, error)
}

// baseGroupFor creates and propagates all-log group.
func baseGroupFor(approved *loglist.LogList, incCount int) (LogGroupInfo, error) {
	baseGroup := LogGroupInfo{Name: BaseName, IsBase: true}
	baseGroup.populate(approved, func(log *loglist.Log) bool { return true })
	err := baseGroup.setMinInclusions(incCount)
	return baseGroup, err
}

// lifetimeInMonths calculates and returns cert lifetime expressed in months flooring incomplete month.
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

// GroupByLogs reverses match-map between Logs and Groups. Returns map from log-URLs to set of Group-names that contain the log.
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
