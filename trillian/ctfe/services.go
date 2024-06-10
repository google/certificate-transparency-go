// Copyright 2024 Google LLC
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

package ctfe

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/cache"
	"github.com/google/certificate-transparency-go/trillian/ctfe/storage"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"k8s.io/klog/v2"

	ct "github.com/google/certificate-transparency-go"
)

// directIssuanceChainService does no special work, relying on the chains
// being serialized in the extraData directly.
type directIssuanceChainService struct {
}

func (s *directIssuanceChainService) BuildLogLeaf(ctx context.Context, chain []*x509.Certificate, logPrefix string, merkleLeaf *ct.MerkleTreeLeaf, isPrecert bool) (*trillian.LogLeaf, error) {
	raw := extractRawCerts(chain)
	// Trillian gRPC
	leaf, err := util.BuildLogLeaf(logPrefix, *merkleLeaf, 0, raw[0], raw[1:], isPrecert)
	if err != nil {
		return nil, fmt.Errorf("failed to build LogLeaf: %s", err)
	}
	return leaf, nil
}

func (s *directIssuanceChainService) FixLogLeaf(ctx context.Context, leaf *trillian.LogLeaf) error {
	return nil
}

func newIndirectIssuanceChainService(s storage.IssuanceChainStorage, c cache.IssuanceChainCache) *indirectIssuanceChainService {
	if s == nil || c == nil {
		panic("storage and cache are required")
	}
	service := &indirectIssuanceChainService{
		storage: s,
		cache:   c,
	}

	return service
}

// indirectIssuanceChainService uses an external storage mechanism to store the chains.
// This feature allows for deduplication of chains, but requires more work to inject the
// chain data back inside the leaves.
type indirectIssuanceChainService struct {
	storage storage.IssuanceChainStorage
	cache   cache.IssuanceChainCache
}

// BuildLogLeaf builds the MerkleTreeLeaf that gets sent to the backend, and make a trillian.LogLeaf for it.
func (s *indirectIssuanceChainService) BuildLogLeaf(ctx context.Context, chain []*x509.Certificate, logPrefix string, merkleLeaf *ct.MerkleTreeLeaf, isPrecert bool) (*trillian.LogLeaf, error) {
	raw := extractRawCerts(chain)

	// Add the chain to storage and cache, and then build log leaf
	issuanceChain, err := asn1.Marshal(raw[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuance chain: %s", err)
	}
	hash, err := s.add(ctx, issuanceChain)
	if err != nil {
		return nil, fmt.Errorf("failed to add issuance chain into CTFE storage: %s", err)
	}
	leaf, err := util.BuildLogLeafWithChainHash(logPrefix, *merkleLeaf, 0, raw[0], hash, isPrecert)
	if err != nil {
		return nil, fmt.Errorf("failed to build LogLeaf: %s", err)
	}
	return leaf, nil
}

// FixLogLeaf recreates and populates the LogLeaf.ExtraData if CTFE storage
// backend is enabled and the type of LogLeaf.ExtraData contains any hash
// (e.g. PrecertChainEntryHash, CertificateChainHash).
func (s *indirectIssuanceChainService) FixLogLeaf(ctx context.Context, leaf *trillian.LogLeaf) error {
	// As the struct stored in leaf.ExtraData is unknown, the only way is to try to unmarshal with each possible struct.
	// Try to unmarshal with ct.PrecertChainEntryHash struct.
	var precertChainHash ct.PrecertChainEntryHash
	if rest, err := tls.Unmarshal(leaf.ExtraData, &precertChainHash); err == nil && len(rest) == 0 {
		var chain []ct.ASN1Cert
		if len(precertChainHash.IssuanceChainHash) > 0 {
			chainBytes, err := s.getByHash(ctx, precertChainHash.IssuanceChainHash)
			if err != nil {
				return err
			}

			if rest, err := asn1.Unmarshal(chainBytes, &chain); err != nil {
				return err
			} else if len(rest) > 0 {
				return fmt.Errorf("IssuanceChain: trailing data %d bytes", len(rest))
			}
		}

		precertChain := ct.PrecertChainEntry{
			PreCertificate:   precertChainHash.PreCertificate,
			CertificateChain: chain,
		}
		extraData, err := tls.Marshal(precertChain)
		if err != nil {
			return err
		}

		leaf.ExtraData = extraData
		return nil
	}

	// Try to unmarshal with ct.CertificateChainHash struct.
	var certChainHash ct.CertificateChainHash
	if rest, err := tls.Unmarshal(leaf.ExtraData, &certChainHash); err == nil && len(rest) == 0 {
		var entries []ct.ASN1Cert
		if len(certChainHash.IssuanceChainHash) > 0 {
			chainBytes, err := s.getByHash(ctx, certChainHash.IssuanceChainHash)
			if err != nil {
				return err
			}

			if rest, err := asn1.Unmarshal(chainBytes, &entries); err != nil {
				return err
			} else if len(rest) > 0 {
				return fmt.Errorf("IssuanceChain: trailing data %d bytes", len(rest))
			}
		}

		certChain := ct.CertificateChain{
			Entries: entries,
		}
		extraData, err := tls.Marshal(certChain)
		if err != nil {
			return err
		}

		leaf.ExtraData = extraData
		return nil
	}

	// Skip if the types are ct.PrecertChainEntry or ct.CertificateChain as there is no hash.
	var precertChain ct.PrecertChainEntry
	if rest, err := tls.Unmarshal(leaf.ExtraData, &precertChain); err == nil && len(rest) == 0 {
		return nil
	}
	var certChain ct.CertificateChain
	if rest, err := tls.Unmarshal(leaf.ExtraData, &certChain); err == nil && len(rest) == 0 {
		return nil
	}

	return fmt.Errorf("unknown extra data type in log leaf: %s", string(leaf.MerkleLeafHash))
}

// getByHash returns the issuance chain with hash as the input.
func (s *indirectIssuanceChainService) getByHash(ctx context.Context, hash []byte) ([]byte, error) {
	// Return if found in cache.
	chain, err := s.cache.Get(ctx, hash)
	if chain != nil || err != nil {
		return chain, err
	}

	// Find in storage if cache miss.
	chain, err = s.storage.FindByKey(ctx, hash)
	if err != nil {
		return nil, err
	}

	// If there is any error from cache set, do not return the error because
	// the chain is still available for read.
	go func(ctx context.Context, hash, chain []byte) {
		if err := s.cache.Set(ctx, hash, chain); err != nil {
			klog.Errorf("failed to set hash and chain into cache: %v", err)
		}
	}(ctx, hash, chain)

	return chain, nil
}

// add adds the issuance chain into the storage and cache and returns the hash
// of the chain.
func (s *indirectIssuanceChainService) add(ctx context.Context, chain []byte) ([]byte, error) {
	hash := issuanceChainHash(chain)

	if err := s.storage.Add(ctx, hash, chain); err != nil {
		return nil, err
	}

	// If there is any error from cache set, do not return the error because
	// the chain is already stored.
	go func(ctx context.Context, hash, chain []byte) {
		if err := s.cache.Set(ctx, hash, chain); err != nil {
			klog.Errorf("failed to set hash and chain into cache: %v", err)
		}
	}(ctx, hash, chain)

	return hash, nil
}

// issuanceChainHash returns the SHA-256 hash of the chain.
func issuanceChainHash(chain []byte) []byte {
	checksum := sha256.Sum256(chain)
	return checksum[:]
}

func extractRawCerts(chain []*x509.Certificate) []ct.ASN1Cert {
	raw := make([]ct.ASN1Cert, len(chain))
	for i, cert := range chain {
		raw[i] = ct.ASN1Cert{Data: cert.Raw}
	}
	return raw
}
