// Copyright 2017 Google LLC. All Rights Reserved.
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

package integration

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keyspb"

	ct "github.com/google/certificate-transparency-go"
)

// ChainGenerator encapsulates objects that can generate certificate chains for testing.
type ChainGenerator interface {
	// CertChain generates a certificate chain.
	CertChain() ([]ct.ASN1Cert, error)
	// PreCertChain generates a precertificate chain, and also returns the leaf TBS data
	PreCertChain() ([]ct.ASN1Cert, []byte, error)
}

// GeneratorFactory is a method that builds a Log-specific ChainGenerator.
type GeneratorFactory func(c *configpb.LogConfig) (ChainGenerator, error)

// SyntheticChainGenerator builds synthetic certificate chains based on
// a template chain and intermediate CA private key.
type SyntheticChainGenerator struct {
	chain    []ct.ASN1Cert
	leafCert *x509.Certificate
	caCert   *x509.Certificate
	// Signer which matches the caCert
	signer   crypto.Signer
	notAfter time.Time
}

// NewSyntheticChainGenerator returns a ChainGenerator that mints synthetic certificates based on the
// given template chain.  The provided signer should match the public key of the first issuer cert.
func NewSyntheticChainGenerator(chain []ct.ASN1Cert, signer crypto.Signer, notAfter time.Time) (ChainGenerator, error) {
	if len(chain) < 2 {
		return nil, fmt.Errorf("chain too short (%d)", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf cert: %v", err)
	}
	issuer, err := x509.ParseCertificate(chain[1].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer cert: %v", err)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	return &SyntheticChainGenerator{
		chain:    chain,
		leafCert: leaf,
		caCert:   issuer,
		signer:   signer,
		notAfter: notAfter,
	}, nil
}

// CertChain builds a new synthetic chain with a fresh leaf cert, changing SubjectKeyId and re-signing.
func (g *SyntheticChainGenerator) CertChain() ([]ct.ASN1Cert, error) {
	cert := *g.leafCert
	cert.NotAfter = g.notAfter
	chain := make([]ct.ASN1Cert, len(g.chain))
	copy(chain[1:], g.chain[1:])

	// Randomize the subject key ID.
	randData := make([]byte, 128)
	if _, err := rand.Read(randData); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}
	cert.SubjectKeyId = randData

	// Create a fresh certificate, signed by the intermediate CA, for the leaf.
	var err error
	chain[0].Data, err = x509.CreateCertificate(rand.Reader, &cert, g.caCert, cert.PublicKey, g.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return chain, nil
}

// PreCertChain builds a new synthetic precert chain; also returns the leaf TBS data.
func (g *SyntheticChainGenerator) PreCertChain() ([]ct.ASN1Cert, []byte, error) {
	prechain := make([]ct.ASN1Cert, len(g.chain))
	copy(prechain[1:], g.chain[1:])

	cert, err := x509.ParseCertificate(g.chain[0].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate to build precert from: %v", err)
	}
	cert.NotAfter = g.notAfter

	prechain[0].Data, err = buildNewPrecertData(cert, g.caCert, g.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// For later verification, build the leaf TBS data that is included in the log.
	tbs, err := buildLeafTBS(prechain[0].Data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build leaf TBSCertificate: %v", err)
	}
	return prechain, tbs, nil
}

// buildLeafTBS builds the raw pre-cert data (a DER-encoded TBSCertificate) that is included
// in the log.
func buildLeafTBS(precertData []byte, preIssuer *x509.Certificate) ([]byte, error) {
	reparsed, err := x509.ParseCertificate(precertData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-parse created precertificate: %v", err)
	}
	return x509.BuildPrecertTBS(reparsed.RawTBSCertificate, preIssuer)
}

// makePreIssuerPrecertChain builds a precert chain where the pre-cert is signed by a new
// pre-issuer intermediate.
func makePreIssuerPrecertChain(chain []ct.ASN1Cert, issuer *x509.Certificate, signer crypto.Signer) ([]ct.ASN1Cert, []byte, error) {
	prechain := make([]ct.ASN1Cert, len(chain)+1)
	copy(prechain[2:], chain[1:])

	// Create a new private key and intermediate CA cert to go with it.
	preSigner, err := keys.NewFromSpec(&keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{
				Curve: keyspb.Specification_ECDSA_P256,
			},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pre-issuer private key: %v", err)
	}

	preIssuerTemplate := *issuer
	preIssuerTemplate.RawSubject = nil
	preIssuerTemplate.Subject.CommonName += "PrecertIssuer"
	preIssuerTemplate.PublicKeyAlgorithm = x509.ECDSA
	preIssuerTemplate.PublicKey = preSigner.Public()
	preIssuerTemplate.ExtKeyUsage = append(preIssuerTemplate.ExtKeyUsage, x509.ExtKeyUsageCertificateTransparency)

	// Set a new subject-key-id for the intermediate (to ensure it's different from the true
	// issuer's subject-key-id).
	randData := make([]byte, 128)
	if _, err := rand.Read(randData); err != nil {
		return nil, nil, fmt.Errorf("failed to read random data: %v", err)
	}
	preIssuerTemplate.SubjectKeyId = randData
	prechain[1].Data, err = x509.CreateCertificate(rand.Reader, &preIssuerTemplate, issuer, preIssuerTemplate.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pre-issuer certificate: %v", err)
	}

	// Parse the pre-issuer back to a fully-populated x509.Certificate.
	preIssuer, err := x509.ParseCertificate(prechain[1].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-parse generated pre-issuer: %v", err)
	}

	cert, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate to build precert from: %v", err)
	}

	prechain[0].Data, err = buildNewPrecertData(cert, preIssuer, preSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	if err := verifyChain(prechain); err != nil {
		return nil, nil, fmt.Errorf("failed to verify just-created prechain: %v", err)
	}

	// The leaf data has the poison removed and the issuance information changed.
	tbs, err := buildLeafTBS(prechain[0].Data, preIssuer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build leaf TBSCertificate: %v", err)
	}
	return prechain, tbs, nil
}

// verifyChain checks that a chain of certificates validates locally.
func verifyChain(rawChain []ct.ASN1Cert) error {
	chain := make([]*x509.Certificate, 0, len(rawChain))
	for i, c := range rawChain {
		cert, err := x509.ParseCertificate(c.Data)
		if err != nil {
			return fmt.Errorf("failed to parse rawChain[%d]: %v", i, err)
		}
		chain = append(chain, cert)
	}

	// First verify signatures cert-by-cert.
	for i := 1; i < len(chain); i++ {
		issuer := chain[i]
		cert := chain[i-1]
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("failed to check signature on rawChain[%d] using rawChain[%d]: %v", i-1, i, err)
		}
	}

	// Now verify the chain as a whole
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		// Don't check path-len constraints
		chain[i].MaxPathLen = -1
		intermediatePool.AddCert(chain[i])
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[len(chain)-1])
	opts := x509.VerifyOptions{
		Roots:             rootPool,
		Intermediates:     intermediatePool,
		DisableTimeChecks: true,
		KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chain[0].UnhandledCriticalExtensions = nil
	chains, err := chain[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("chain[0].Verify(%+v) failed: %v", opts, err)
	}
	if len(chains) == 0 {
		return errors.New("no path to root found when trying to validate chains")
	}

	return nil
}

// SyntheticGeneratorFactory returns a function that creates per-Log ChainGenerator instances
// that create synthetic certificates (details of which are specified by the arguments).
func SyntheticGeneratorFactory(testDir, leafNotAfter string) (GeneratorFactory, error) {
	leafChain, err := GetChain(testDir, "leaf01.chain")
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	signer, err := MakeSigner(testDir)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve signer for re-signing: %v", err)
	}
	var notAfterOverride time.Time
	if leafNotAfter != "" {
		notAfterOverride, err = time.Parse(time.RFC3339, leafNotAfter)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf notAfter: %v", err)
		}
	}
	// Build a synthetic generator for each target log.
	return func(c *configpb.LogConfig) (ChainGenerator, error) {
		notAfter := notAfterOverride
		if notAfter.IsZero() {
			var err error
			notAfter, err = NotAfterForLog(c)
			if err != nil {
				return nil, fmt.Errorf("failed to determine notAfter for %s: %v", c.Prefix, err)
			}
		}
		return NewSyntheticChainGenerator(leafChain, signer, notAfter)
	}, nil
}
