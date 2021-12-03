// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package verifier is designed to verify the signatures produced by a witness.
package verifier

import (
	"crypto"
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/internal/witness/api"
	"github.com/google/certificate-transparency-go/tls"
)

// WitnessVerifier consists of a CT signature verifier.
type WitnessVerifier struct {
	SigVerifier *ct.SignatureVerifier
}

// NewWitnessVerifier creates a witness signature verifier from a public key.
func NewWitnessVerifier(pk crypto.PublicKey) (*WitnessVerifier, error) {
	sv, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature verifier: %v", err)
	}
	return &WitnessVerifier{SigVerifier: sv}, nil
}

// VerifySignature finds and verifies this witness' signature on a cosigned STH.
// This may mean that there are other witness signatures that remain unverified,
// so future implementations may want to take in multiple signature verifiers
// like in the Note package (https://pkg.go.dev/golang.org/x/mod/sumdb/note).
func (wv WitnessVerifier) VerifySignature(sth api.CosignedSTH) error {
	if len(sth.WitnessSigs) == 0 {
		return errors.New("no witness signature present in the STH")
	}
	sigData, err := tls.Marshal(sth.SignedTreeHead)
	if err != nil {
		return fmt.Errorf("failed to marshal internal STH: %v", err)
	}
	for _, sig := range sth.WitnessSigs {
		// If we find a signature that verifies then we're okay.
		if err := wv.SigVerifier.VerifySignature(sigData, tls.DigitallySigned(sig)); err == nil {
			return nil
		}
	}
	return errors.New("failed to verify any signature for this witness")
}
