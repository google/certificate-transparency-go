// Copyright 2014 Google Inc. All Rights Reserved.
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

package scanner

import (
	"math/big"
	"regexp"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

// Matcher describes how to match certificates and precertificates; clients should implement this interface
// to perform their own match criteria.
type Matcher interface {
	// CertificateMatches is called by the scanner for each X509 Certificate found in the log.
	// The implementation should return true if the passed Certificate is interesting, and false otherwise.
	CertificateMatches(*x509.Certificate) bool

	// PrecertificateMatches is called by the scanner for each CT Precertificate found in the log.
	// The implementation should return true if the passed Precertificate is interesting, and false otherwise.
	PrecertificateMatches(*ct.Precertificate) bool
}

// MatchAll is a Matcher which will match every possible Certificate and Precertificate.
type MatchAll struct{}

// CertificateMatches returns true if the given cert should match; in this case, always.
func (m MatchAll) CertificateMatches(_ *x509.Certificate) bool {
	return true
}

// PrecertificateMatches returns true if the given precert should match, in this case, always.
func (m MatchAll) PrecertificateMatches(_ *ct.Precertificate) bool {
	return true
}

// MatchNone is a Matcher which will never match any Certificate or Precertificate.
type MatchNone struct{}

// CertificateMatches returns true if the given cert should match; in this case, never.
func (m MatchNone) CertificateMatches(_ *x509.Certificate) bool {
	return false
}

// PrecertificateMatches returns true if the given cert should match; in this case, never.
func (m MatchNone) PrecertificateMatches(_ *ct.Precertificate) bool {
	return false
}

// MatchSerialNumber performs a match for a specific serial number.
type MatchSerialNumber struct {
	SerialNumber big.Int
}

// CertificateMatches returns true if the given cert should match; in this
// case, only if the serial number matches.
func (m MatchSerialNumber) CertificateMatches(c *x509.Certificate) bool {
	return c.SerialNumber.String() == m.SerialNumber.String()
}

// PrecertificateMatches returns true if the given cert should match; in this
// case, only if the serial number matches.
func (m MatchSerialNumber) PrecertificateMatches(p *ct.Precertificate) bool {
	return p.TBSCertificate.SerialNumber.String() == m.SerialNumber.String()
}

// MatchSubjectRegex is a Matcher which will use CertificateSubjectRegex and PrecertificateSubjectRegex
// to determine whether Certificates and Precertificates are interesting.
// The two regexes are tested against Subject CN (Common Name) as well as all
// Subject Alternative Names
type MatchSubjectRegex struct {
	CertificateSubjectRegex    *regexp.Regexp
	PrecertificateSubjectRegex *regexp.Regexp
}

// CertificateMatches returns true if either CN or any SAN of c matches m.CertificateSubjectRegex.
func (m MatchSubjectRegex) CertificateMatches(c *x509.Certificate) bool {
	if m.CertificateSubjectRegex.FindStringIndex(c.Subject.CommonName) != nil {
		return true
	}
	for _, alt := range c.DNSNames {
		if m.CertificateSubjectRegex.FindStringIndex(alt) != nil {
			return true
		}
	}
	return false
}

// PrecertificateMatches returns true if either CN or any SAN of p matches m.PrecertificateSubjectRegex.
func (m MatchSubjectRegex) PrecertificateMatches(p *ct.Precertificate) bool {
	if m.PrecertificateSubjectRegex.FindStringIndex(p.TBSCertificate.Subject.CommonName) != nil {
		return true
	}
	for _, alt := range p.TBSCertificate.DNSNames {
		if m.PrecertificateSubjectRegex.FindStringIndex(alt) != nil {
			return true
		}
	}
	return false
}

// MatchIssuerRegex matches on issuer CN (common name) by regex
type MatchIssuerRegex struct {
	CertificateIssuerRegex    *regexp.Regexp
	PrecertificateIssuerRegex *regexp.Regexp
}

// CertificateMatches returns true if the given cert's CN matches.
func (m MatchIssuerRegex) CertificateMatches(c *x509.Certificate) bool {
	return m.CertificateIssuerRegex.FindStringIndex(c.Issuer.CommonName) != nil
}

// PrecertificateMatches returns true if the given precert's CN matches.
func (m MatchIssuerRegex) PrecertificateMatches(p *ct.Precertificate) bool {
	return m.PrecertificateIssuerRegex.FindStringIndex(p.TBSCertificate.Issuer.CommonName) != nil
}
