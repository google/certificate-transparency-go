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

package ctpolicy

import (
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/x509"
)

// AppleCTPolicy implements logic for complying with Apple's CT log policy.
type AppleCTPolicy struct{}

// LogsByGroup describes submission requirements for embedded SCTs according to
// https://support.apple.com/en-us/HT205280. Returns data even when error emitted.
func (appleP AppleCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist.LogList) (LogPolicyData, error) {
	var incCount int
	switch m := lifetimeInMonths(cert); {
	case m < 15:
		incCount = 2
	case m <= 27:
		incCount = 3
	case m <= 39:
		incCount = 4
	default:
		incCount = 5
	}
	baseGroup, err := BaseGroupFor(approved, incCount)
	groups := LogPolicyData{baseGroup.Name: &baseGroup}
	return groups, err
}

// Name returns label for the submission policy.
func (appleP AppleCTPolicy) Name() string {
	return "Apple"
}

// Description returns human-readable submission requirements.
func (appleP AppleCTPolicy) Description() string {
	return `Certificate Transparency policy according to https://support.apple.com/en-us/HT205280.\n
	* minimal total number of Logs certificate should get submitted is guided by certificate lifetime L:\n
		L < 15 months  ==> 2\n
		15 months <= L <= 27 months  ==> 3\n
		27 months < L <= 39 months  ==> 4\n
		39 months < L  ==> 5\n`
}
