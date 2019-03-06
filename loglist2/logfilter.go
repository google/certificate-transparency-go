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

package loglist2

import (
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
)

// LogRoots maps Log-URLs (stated at LogList) to the pools of their accepted
// root-certificates.
type LogRoots map[string]*ctfe.PEMCertPool

// SelectUsable creates a new LogList containing only usable logs from
// the original.
func (ll *LogList) SelectUsable() LogList {
	var active LogList
	for _, op := range ll.Operators {
		activeOp := *op
		activeOp.Logs = []*Log{}
		for _, l := range op.Logs {
			if l.State != nil && l.State.Usable != nil {
				activeOp.Logs = append(activeOp.Logs, l)
			}
		}
		if len(activeOp.Logs) > 0 {
			active.Operators = append(active.Operators, &activeOp)
		}
	}
	return active
}

// RootCompatible creates a new LogList containing only the logs of original
// LogList that are compatible with the provided cert-chain, according to
// the passed in collection of per-log roots. Logs that are missing from
// the collection are treated as always compatible and included, even if
// an empty cert chain is passed in.
// Cert-chain when provided is expected to be full: ending with CA-cert.
func (ll *LogList) RootCompatible(rootedChain []*x509.Certificate, roots LogRoots) LogList {
	var compatible LogList

	// When chain info is not available, collect Logs with no root info as
	// compatible.
	chainIsEmpty := len(rootedChain) == 0

	// Check whether chain is ending with CA-cert.
	if !chainIsEmpty && !rootedChain[len(rootedChain)-1].IsCA {
		glog.Warningf("Compatible method expects fully rooted chain, while last cert of the chain provided is not root")
		return compatible
	}

	for _, op := range ll.Operators {
		compatibleOp := *op
		compatibleOp.Logs = []*Log{}
		for _, l := range op.Logs {
			// If root set is not defined, we treat Log as compatible assuming no
			// knowledge of its roots.
			if _, ok := roots[l.URL]; !ok {
				compatibleOp.Logs = append(compatibleOp.Logs, l)
				continue
			}

			if chainIsEmpty {
				continue
			}

			// Check root is accepted.
			if roots[l.URL].Included(rootedChain[len(rootedChain)-1]) {
				compatibleOp.Logs = append(compatibleOp.Logs, l)
			}
		}
		if len(compatibleOp.Logs) > 0 {
			compatible.Operators = append(compatible.Operators, &compatibleOp)
		}
	}
	return compatible
}
