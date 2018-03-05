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

// Package audit provides utility functions that may be useful to Certificate
// Transparency Log clients.
package audit

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

var emptyHash = [32]byte{}

// B64LeafHash calculates the base64-encoded leaf hash of the certificate or
// precertificate at chain[0] that sct was issued for.
//
// If using this function to calculate the leaf hash for an X509 certificate
// (i.e. not a precertificate) then it is enough to just provide the end entity
// certificate in chain.  However, if using this function to calculate the leaf
// hash for a precertificate then the issuing certificate must also be provided
// in chain.  When providing a certificate chain the leaf certificate must be at
// chain[0].
//
// sct is required because the SCT timestamp is used to calculate the leaf hash.
// Leaf hashes are unique to (pre)certificate-SCT pairs.
func B64LeafHash(chain []*x509.Certificate, sct *ct.SignedCertificateTimestamp) (string, error) {
	hash, err := LeafHash(chain, sct)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// LeafHash calculates the leaf hash of the certificate or precertificate at
// chain[0] that sct was issued for.
//
// If using this function to calculate the leaf hash for an X509 certificate
// (i.e. not a precertificate) then it is enough to just provide the end entity
// certificate in chain.  However, if using this function to calculate the leaf
// hash for a precertificate then the issuing certificate must also be provided
// in chain.  When providing a certificate chain the leaf certificate must be at
// chain[0].
//
// sct is required because the SCT timestamp is used to calculate the leaf hash.
// Leaf hashes are unique to (pre)certificate-SCT pairs.
func LeafHash(chain []*x509.Certificate, sct *ct.SignedCertificateTimestamp) ([32]byte, error) {
	if len(chain) == 0 {
		return emptyHash, errors.New("chain is empty")
	}
	if sct == nil {
		return emptyHash, errors.New("sct is nil")
	}

	certType := ct.X509LogEntryType
	if IsPrecert(chain[0]) {
		certType = ct.PrecertLogEntryType
	}
	leaf, err := ct.MerkleTreeLeafFromChain(chain, certType, sct.Timestamp)
	if err != nil {
		return emptyHash, fmt.Errorf("error creating MerkleTreeLeaf: %s", err)
	}
	leafData, err := tls.Marshal(*leaf)
	if err != nil {
		return emptyHash, fmt.Errorf("error tls-encoding MerkleTreeLeaf: %s", err)
	}

	data := append([]byte{0}, leafData...)
	leafHash := sha256.Sum256(data)
	return leafHash, nil
}

// IsPrecert checks whether the given certificate is a precertificate.
func IsPrecert(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(x509.OIDExtensionCTPoison) {
			return true
		}
	}
	return false
}

// VerifySCT takes the public key of a Certificate Transparency Log, a
// certificate chain, and an SCT and verifies whether the SCT is a valid SCT for
// the certificate at chain[0], signed by the Log that the public key belongs
// to.  If the SCT does not verify, an error will be returned.
//
// If using this function to verify an SCT for an X509 certificate (i.e. not a
// precertificate) then it is enough to just provide the end entity certificate
// in chain.  However, if using this function to verify an SCT for a
// precertificate then the issuing certificate must also be provided in chain.
// When providing a certificate chain the leaf certificate must be at chain[0].
func VerifySCT(pubKey crypto.PublicKey, chain []*x509.Certificate, sct *ct.SignedCertificateTimestamp) error {
	certType := ct.X509LogEntryType
	if IsPrecert(chain[0]) {
		certType = ct.PrecertLogEntryType
	}
	leaf, err := ct.MerkleTreeLeafFromChain(chain, certType, sct.Timestamp)
	if err != nil {
		return fmt.Errorf("error creating MerkleTreeLeaf: %s", err)
	}

	s, err := ct.NewSignatureVerifier(pubKey)
	if err != nil {
		return fmt.Errorf("error creating signature verifier: %s", err)
	}

	entry := ct.LogEntry{Leaf: *leaf}
	return s.VerifySCTSignature(*sct, entry)
}

// VerifySCTB64PublicKey takes the base64-encoded public key of a Certificate
// Transparency Log, a certificate chain, and an SCT and verifies whether the
// SCT is a valid SCT for the certificate at chain[0], signed by the Log that
// the public key belongs to.  If the SCT does not verify, an error will be
// returned.
//
// If using this function to verify an SCT for an X509 certificate (i.e. not a
// precertificate) then it is enough to just provide the end entity certificate
// in chain.  However, if using this function to verify an SCT for a
// precertificate then the issuing certificate must also be provided in chain.
// When providing a certificate chain the leaf certificate must be at chain[0].
func VerifySCTB64PublicKey(b64PubKey string, chain []*x509.Certificate, sct *ct.SignedCertificateTimestamp) error {
	pk, err := ParseB64PublicKey(b64PubKey)
	if err != nil {
		return fmt.Errorf("error parsing public key: %s", err)
	}
	return VerifySCT(pk, chain, sct)
}
