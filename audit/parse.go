// Copyright 2016 Google Inc. All Rights Reserved.
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

package audit

import (
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

// ParseCertificateFromPEM parses an X509 certificate from data in PEM format.
func ParseCertificateFromPEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, errors.New("trailing data found after PEM block")
	}
	if block == nil {
		return nil, errors.New("PEM block is nil")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// ParseChainFromPEM parses an X509 certificate chain from data in PEM format.
func ParseChainFromPEM(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return chain, nil
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block is not a CERTIFICATE")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("failed to parse certificate")
		}
		chain = append(chain, cert)
	}
}

// ParseB64PublicKey parses a base64-encoded public key.
func ParseB64PublicKey(b64PubKey string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64PubKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %s", err)
	}
	return x509.ParsePKIXPublicKey(der)
}

// ParseSCTsFromPEMCert parses any SCTs that are embedded in the PEM-formatted
// certificate provided.
func ParseSCTsFromPEMCert(data []byte) ([]*ct.SignedCertificateTimestamp, error) {
	cert, err := ParseCertificateFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}
	return ParseSCTsFromSCTList(&cert.SCTList)
}

// ParseSCTsFromSCTList parses each of the SCTs contained within an
// x509.SignedCertificateTimestampList, and returns them as a slice of
// ct.SignedCertificateTimestamps
func ParseSCTsFromSCTList(sctList *x509.SignedCertificateTimestampList) ([]*ct.SignedCertificateTimestamp, error) {
	var scts []*ct.SignedCertificateTimestamp
	for i, data := range sctList.SCTList {
		var sct ct.SignedCertificateTimestamp
		_, err := tls.Unmarshal(data.Val, &sct)
		if err != nil {
			return nil, fmt.Errorf("error parsing SCT number %d: %s", i, err)
		}
		scts = append(scts, &sct)
	}
	return scts, nil
}
