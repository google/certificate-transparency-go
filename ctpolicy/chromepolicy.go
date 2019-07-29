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
	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/x509"
)

// ChromeCTPolicy implements logic for complying with Chrome's CT log policy
type ChromeCTPolicy struct {
}

// updateIfNotNil picks err argument iff it is not nil, oldErr otherwise.
func updateIfNotNil(oldErr error, err error) error {
	if err != nil {
		return err
	}
	return oldErr
}

// LogsByGroup describes submission requirements for embedded SCTs according to
// https://github.com/chromium/ct-policy/blob/master/ct_policy.md#qualifying-certificate.
// Error warns on inability to reach minimal number of Logs requirement due to
// inadequate number of Logs within LogList.
func (chromeP ChromeCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist.LogList) (LogPolicyData, error) {
	var outerror error
	googGroup := LogGroupInfo{Name: "Google-operated", IsBase: false}
	googGroup.populate(approved, func(log *loglist.Log) bool { return log.GoogleOperated() })
	err := googGroup.setMinInclusions(1)
	outerror = updateIfNotNil(outerror, err)

	nonGoogGroup := LogGroupInfo{Name: "Non-Google-operated", IsBase: false}
	nonGoogGroup.populate(approved, func(log *loglist.Log) bool { return !log.GoogleOperated() })
	err = nonGoogGroup.setMinInclusions(1)
	outerror = updateIfNotNil(outerror, err)

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
	outerror = updateIfNotNil(outerror, err)
	groups := LogPolicyData{
		googGroup.Name:    &googGroup,
		nonGoogGroup.Name: &nonGoogGroup,
		baseGroup.Name:    baseGroup,
	}
	return groups, outerror
}

// LogsByGroup describes submission requirements for embedded SCTs according to
// https://github.com/chromium/ct-policy/blob/master/ct_policy.md#qualifying-certificate.
// Error warns on inability to reach minimal number of Logs requirement due to
// inadequate number of Logs within LogList.
func (chromeP ChromeCTPolicy) LogsByGroup2(cert *x509.Certificate, approved *loglist2.LogList) (LogPolicyData, error) {
	var outerror error
	googGroup := LogGroupInfo{Name: "Google-operated", IsBase: false}
	googGroup.populate2(approved, func(op *loglist2.Operator) bool { return op.GoogleOperated() })
	err := googGroup.setMinInclusions(1)
	outerror = updateIfNotNil(outerror, err)

	nonGoogGroup := LogGroupInfo{Name: "Non-Google-operated", IsBase: false}
	nonGoogGroup.populate2(approved, func(op *loglist2.Operator) bool { return !op.GoogleOperated() })
	err = nonGoogGroup.setMinInclusions(1)
	outerror = updateIfNotNil(outerror, err)

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
	baseGroup, err := BaseGroupFor2(approved, incCount)
	outerror = updateIfNotNil(outerror, err)
	groups := LogPolicyData{
		googGroup.Name:    &googGroup,
		nonGoogGroup.Name: &nonGoogGroup,
		baseGroup.Name:    baseGroup,
	}
	return groups, outerror
}

// Name returns label for the submission policy.
func (chromeP ChromeCTPolicy) Name() string {
	return "Chrome"
}
