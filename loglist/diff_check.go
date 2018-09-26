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

package loglist

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
  "sort"
)

// warningCollector is an interface for structs that have the capability to
// collect warnings.  It is used to report warnings from the various check
// functions defined in this file.
type warningCollector interface {
	addWarning(string)
}

type warningList struct {
	warnings []string
}

func (wl *warningList) addWarning(w string) {
	if w != "" {
		wl.warnings = append(wl.warnings, w)
	}
}

// Check: operators lists are identical.
func checkOperators(master_ll *LogList, branch_ll *LogList, wc warningCollector) {
	if !reflect.DeepEqual(master_ll.Operators, branch_ll.Operators) {
		wc.addWarning("Operators lists are not identical")
	}
}

// Check: 2 logs are identical (apart from description and STH).
func checkLogPair(log_one *Log, log_two *Log, wc warningCollector) {
	// Description and STH comparison are omitted.

	if !bytes.Equal(log_one.Key, log_two.Key) {
		wc.addWarning(fmt.Sprintf(
			"Log %s and log %s have different keys.",
			log_one.Description, log_two.Description))
	}
	if log_one.MaximumMergeDelay != log_two.MaximumMergeDelay {
		wc.addWarning(fmt.Sprintf(
			"Maximum merge delay mismatch for logs %s and %s: %d != %d.",
			log_one.Description, log_two.Description, log_one.MaximumMergeDelay, log_two.MaximumMergeDelay))
	}
	sort.Sort(sort.IntSlice(log_one.OperatedBy))
	sort.Sort(sort.IntSlice(log_two.OperatedBy))
	if !reflect.DeepEqual(log_one.OperatedBy, log_two.OperatedBy) {
		wc.addWarning(fmt.Sprintf(
			"Operators mismatch for logs %s and %s",
			log_one.Description, log_two.Description))
	}
	if log_one.URL != log_two.URL {
		wc.addWarning(fmt.Sprintf(
			"URL mismatch for logs %s and %s: %s != %s.",
			log_one.Description, log_two.Description, log_one.URL, log_two.URL))
	}
	if log_one.DisqualifiedAt != log_two.DisqualifiedAt {
		wc.addWarning(fmt.Sprintf(
			"Disqualified-at-timing mismatch for logs %s and %s.",
			log_one.Description, log_two.Description))
	}
	if log_one.URL != log_two.URL {
		wc.addWarning(fmt.Sprintf(
			"DNS API mismatch for logs %s and %s: %s != %s.",
			log_one.Description, log_two.Description, log_one.DNSAPIEndpoint, log_two.DNSAPIEndpoint))
	}
}

// Check: logs present at branched list either have key matched entry at master
// list or are absent from master.
func checkLogs(master_ll *LogList, branch_ll *LogList, wc warningCollector) {
	for _, log := range branch_ll.Logs {
		if master_entry := master_ll.FindLogByKey(log.Key); master_entry != nil {
			checkLogPair(master_entry, &log, wc)
		}
	}
}

func CheckBranch(master_ll *LogList, branch_ll *LogList) ([]string, error) {
	w := &warningList{}
	checkOperators(master_ll, branch_ll, w)
	checkLogs(master_ll, branch_ll, w)
	if len(w.warnings) > 0 {
		return w.warnings, errors.New("Log list branch validation failed")
	}
	return nil, nil
}
