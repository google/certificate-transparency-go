// Copyright 2022 Google LLC. All Rights Reserved.
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

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/spf13/cobra"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"k8s.io/klog/v2"
)

var (
	leafHash  string
	certChain string
	timestamp int64
	treeSize  uint64
)

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("get-inclusion-proof %s {--leaf_hash=hash | --cert_chain=file} [--timestamp=ts] [--size=N]", connectionFlags),
		Aliases: []string{"getinclusionproof", "inclusion-proof", "inclusion"},
		Short:   "Fetch and verify the inclusion proof for an entry",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runGetInclusionProof(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&leafHash, "leaf_hash", "", "Leaf hash to retrieve (as hex string or base64)")
	cmd.Flags().StringVar(&certChain, "cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
	cmd.Flags().Int64Var(&timestamp, "timestamp", 0, "Timestamp to use for inclusion checking")
	cmd.Flags().Uint64Var(&treeSize, "size", 0, "Tree size to query at")
	rootCmd.AddCommand(&cmd)
}

// runGetInclusionProof runs the get-inclusion-proof command.
func runGetInclusionProof(ctx context.Context) {
	logClient := connect(ctx)
	var hash []byte
	if len(leafHash) > 0 {
		var err error
		hash, err = hashFromString(leafHash)
		if err != nil {
			klog.Exitf("Invalid --leaf_hash supplied: %v", err)
		}
	} else if len(certChain) > 0 {
		// Build a leaf hash from the chain and a timestamp.
		chain, entryTimestamp := chainFromFile(certChain)
		if timestamp != 0 {
			entryTimestamp = timestamp // Use user-specified timestamp.
		}
		if entryTimestamp == 0 {
			klog.Exit("No timestamp available to accompany certificate")
		}

		var leafEntry *ct.MerkleTreeLeaf
		cert, err := x509.ParseCertificate(chain[0].Data)
		if x509.IsFatal(err) {
			klog.Warningf("Failed to parse leaf certificate: %v", err)
			leafEntry = ct.CreateX509MerkleTreeLeaf(chain[0], uint64(entryTimestamp))
		} else if cert.IsPrecertificate() {
			leafEntry, err = ct.MerkleTreeLeafFromRawChain(chain, ct.PrecertLogEntryType, uint64(entryTimestamp))
			if err != nil {
				klog.Exitf("Failed to build pre-certificate leaf entry: %v", err)
			}
		} else {
			leafEntry = ct.CreateX509MerkleTreeLeaf(chain[0], uint64(entryTimestamp))
		}

		leafHash, err := ct.LeafHashForLeaf(leafEntry)
		if err != nil {
			klog.Exitf("Failed to create hash of leaf: %v", err)
		}
		hash = leafHash[:]

		// Print a warning if this timestamp is still within the MMD window.
		when := ct.TimestampToTime(uint64(entryTimestamp))
		if age := time.Since(when); age < logMMD {
			klog.Warningf("WARNING: Timestamp (%v) is with MMD window (%v), log may not have incorporated this entry yet.", when, logMMD)
		}
	}
	if len(hash) != sha256.Size {
		klog.Exit("No leaf hash available")
	}
	getInclusionProofForHash(ctx, logClient, hash)
}

func getInclusionProofForHash(ctx context.Context, logClient client.CheckLogClient, hash []byte) {
	var sth *ct.SignedTreeHead
	size := treeSize
	if size <= 0 {
		var err error
		sth, err = logClient.GetSTH(ctx)
		if err != nil {
			exitWithDetails(err)
		}
		size = sth.TreeSize
	}
	// Display the inclusion proof.
	rsp, err := logClient.GetProofByHash(ctx, hash, size)
	if err != nil {
		exitWithDetails(err)
	}
	fmt.Printf("Inclusion proof for index %d in tree of size %d:\n", rsp.LeafIndex, size)
	for _, e := range rsp.AuditPath {
		fmt.Printf("  %x\n", e)
	}
	if sth != nil {
		// If we retrieved an STH we can verify the proof.
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(rsp.LeafIndex), sth.TreeSize, hash, rsp.AuditPath, sth.SHA256RootHash[:]); err != nil {
			klog.Exitf("Failed to VerifyInclusion(%d, %d)=%v", rsp.LeafIndex, sth.TreeSize, err)
		}
		fmt.Printf("Verified that hash %x + proof = root hash %x\n", hash, sth.SHA256RootHash)
	}
}

func chainFromFile(filename string) ([]ct.ASN1Cert, int64) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		klog.Exitf("Failed to read certificate file: %v", err)
	}
	rest := contents
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	if len(chain) == 0 {
		klog.Exitf("No certificates found in %s", certChain)
	}

	// Also look for something like a text timestamp for convenience.
	var timestamp int64
	tsRE := regexp.MustCompile(`Timestamp[:=](\d+)`)
	for _, line := range strings.Split(string(contents), "\n") {
		x := tsRE.FindStringSubmatch(line)
		if len(x) > 1 {
			timestamp, err = strconv.ParseInt(x[1], 10, 64)
			if err != nil {
				break
			}
		}
	}
	return chain, timestamp
}
