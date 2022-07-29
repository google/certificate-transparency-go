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
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/certificate-transparency-go/client"
	"github.com/spf13/cobra"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"k8s.io/klog/v2"
)

var (
	treeHash string
	prevSize uint64
	prevHash string
)

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("get-consistency-proof %s --size=N --tree_hash=hash --prev_size=N --prev_hash=hash", connectionFlags),
		Aliases: []string{"getconsistencyproof", "consistency-proof", "consistency"},
		Short:   "Fetch and verify a consistency proof between two tree states",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runGetConsistencyProof(cmd.Context())
		},
	}
	// TODO(pavelkalinnikov): Don't share this parameter with get-inclusion-proof.
	cmd.Flags().Uint64Var(&treeSize, "size", 0, "Tree size to query at")
	cmd.Flags().StringVar(&treeHash, "tree_hash", "", "Tree hash to check against (as hex string or base64)")
	cmd.Flags().Uint64Var(&prevSize, "prev_size", 0, "Previous tree size to get consistency against")
	cmd.Flags().StringVar(&prevHash, "prev_hash", "", "Previous tree hash to check against (as hex string or base64)")
	rootCmd.AddCommand(&cmd)
}

// runGetConsistencyProof runs the get-consistency-proof command.
func runGetConsistencyProof(ctx context.Context) {
	logClient := connect(ctx)
	if treeSize <= 0 {
		klog.Exit("No valid --size supplied")
	}
	if prevSize <= 0 {
		klog.Exit("No valid --prev_size supplied")
	}
	var hash1, hash2 []byte
	if prevHash != "" {
		var err error
		hash1, err = hashFromString(prevHash)
		if err != nil {
			klog.Exitf("Invalid --prev_hash: %v", err)
		}
	}
	if treeHash != "" {
		var err error
		hash2, err = hashFromString(treeHash)
		if err != nil {
			klog.Exitf("Invalid --tree_hash: %v", err)
		}
	}
	if (hash1 != nil) != (hash2 != nil) {
		klog.Exitf("Need both --prev_hash and --tree_hash or neither")
	}
	getConsistencyProofBetween(ctx, logClient, prevSize, treeSize, hash1, hash2)
}

func getConsistencyProofBetween(ctx context.Context, logClient client.CheckLogClient, first, second uint64, prevHash, treeHash []byte) {
	pf, err := logClient.GetSTHConsistency(ctx, uint64(first), uint64(second))
	if err != nil {
		exitWithDetails(err)
	}
	fmt.Printf("Consistency proof from size %d to size %d:\n", first, second)
	for _, e := range pf {
		fmt.Printf("  %x\n", e)
	}
	if prevHash == nil || treeHash == nil {
		return
	}
	// We have tree hashes so we can verify the proof.
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, first, second, pf, prevHash, treeHash); err != nil {
		klog.Exitf("Failed to VerifyConsistency(%x @size=%d, %x @size=%d): %v", prevHash, first, treeHash, second, err)
	}
	fmt.Printf("Verified that hash %x @%d + proof = hash %x @%d\n", prevHash, first, treeHash, second)
}

func hashFromString(input string) ([]byte, error) {
	hash, err := hex.DecodeString(input)
	if err == nil && len(hash) == sha256.Size {
		return hash, nil
	}
	hash, err = base64.StdEncoding.DecodeString(input)
	if err == nil && len(hash) == sha256.Size {
		return hash, nil
	}
	return nil, fmt.Errorf("hash value %q failed to parse as 32-byte hex or base64", input)
}
