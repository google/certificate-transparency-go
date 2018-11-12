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

	"github.com/google/certificate-transparency-go/x509"
)

// LogRoots maps Log-URLs (stated at LogList) to the list of their accepted root-certificates.
type LogRoots map[string][]*x509.Certificate

// ActiveLogs creates a new LogList containing only non-disqualified non-frozen logs from the original.
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

// Compatible creates a new LogList containing only logs of original LogList compatible with cert-chain provided. Cert-chain is expected to be full: ending with CA-cert.
func (ll *LogList) Compatible(rootedChain []*x509.Certificate, roots LogRoots) LogList {
	var compatible LogList
	// Keep all the operators.
	compatible.Operators = ll.Operators
	if len(rootedChain) == 0 || !rootedChain[len(rootedChain)-1].IsCA {
		return compatible
	}
	for _, l := range ll.Logs {
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
