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

package ctpolicy

import (
	"errors"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

// AppleCTPolicy implements logic for complying with Apple's CT log policy.
type AppleCTPolicy struct{}

// LogsByGroup describes submission requirements for embedded SCTs according to
// https://support.apple.com/en-us/HT205280. Returns an error if it's not
// possible to satisfy the policy with the provided loglist.
func (appleP AppleCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist3.LogList) (LogPolicyData, error) {
	groups := LogPolicyData{}
	for _, op := range approved.Operators {
		info := &LogGroupInfo{Name: op.Name, IsBase: false}
		info.LogURLs = make(map[string]bool)
		info.LogWeights = make(map[string]float32)
		for _, l := range op.Logs {
			info.LogURLs[l.URL] = true
			info.LogWeights[l.URL] = 1.0
		}
		groups[info.Name] = info
	}
	var incCount int
	switch t := certLifetime(cert); {
	case t <= 180*dayDuration:
		incCount = 2
	case t <= 398*dayDuration && t > 180*dayDuration:
		incCount = 3
	default:
		return nil, errors.New("certificate limetime out of bounds")
	}
	baseGroup, err := BaseGroupFor(approved, incCount)
	if err != nil {
		return nil, err
	}
	baseGroup.MinDistinctOperators = minDistinctOperators
	groups[baseGroup.Name] = baseGroup
	return groups, nil
}

// Name returns label for the submission policy.
func (appleP AppleCTPolicy) Name() string {
	return "Apple"
}
