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
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
)

// LogRoots maps Log-URLs (stated at LogList) to the list of their accepted
// root-certificates.
type LogRoots map[string][]*x509.Certificate

// ActiveLogs creates a new LogList containing only non-disqualified non-frozen
// logs from the original.
func (ll *LogList) ActiveLogs() LogList {
	var active LogList
	// Keep all the operators.
	active.Operators = ll.Operators
	for _, l := range ll.Logs {
		if (l.DisqualifiedAt <= 0 && l.FinalSTH == nil) || time.Until(time.Unix(int64(l.DisqualifiedAt), 0)) > 0 {
			active.Logs = append(active.Logs, l)
		}
	}
	return active
}

// Compatible creates a new LogList containing only the logs of original
// LogList that are compatible with the provided cert-chain, according to
// the passed in collection of per-log roots. Logs that are missing from
// the collection are treated as always compatible and included, even if
// an empty cert chain is passed in.
// Cert-chain when provided is expected to be full: ending with CA-cert.
func (ll *LogList) Compatible(rootedChain []*x509.Certificate, roots LogRoots) LogList {
	var compatible LogList
	// Keep all the operators.
	compatible.Operators = ll.Operators

	// When chain info is not available, collect Logs with no root info as
	// compatible.
	chainIsEmpty := len(rootedChain) == 0

	// Check whether chain is ending with CA-cert.
	if !chainIsEmpty && !rootedChain[len(rootedChain)-1].IsCA {
		glog.Warningf("Compatibale method expects fully rooted chain, while last cert of the chain provided is not root")
		return compatible
	}

	for _, l := range ll.Logs {
		// If root set is not defined, we treat Log as compatible assuming no
		// knowledge of its roots.
		if _, ok := roots[l.URL]; !ok {
			compatible.Logs = append(compatible.Logs, l)
			continue
		}
		if chainIsEmpty {
			continue
		}

		// Check root is accepted.
		for _, r := range roots[l.URL] {
			if r.Equal(rootedChain[len(rootedChain)-1]) {
				compatible.Logs = append(compatible.Logs, l)
				break
			}
		}
	}
	return compatible
}
