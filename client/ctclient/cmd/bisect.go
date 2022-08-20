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
	"fmt"
	"sort"

	ct "github.com/google/certificate-transparency-go"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("bisect %s --timestamp=ts [--chain] [--text=false]", connectionFlags),
		Aliases: []string{"find-timestamp"},
		Short:   "Find a log entry by timestamp",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runBisect(cmd.Context())
		},
	}
	cmd.Flags().Int64Var(&timestamp, "timestamp", 0, "Timestamp to use for inclusion checking")
	// TODO(pavelkalinnikov): Don't share these parameters with get-entries.
	cmd.Flags().BoolVar(&chainOut, "chain", false, "Display entire certificate chain")
	cmd.Flags().BoolVar(&textOut, "text", true, "Display certificates as text")
	rootCmd.AddCommand(&cmd)
}

// runBisect runs the bisect command.
func runBisect(ctx context.Context) {
	logClient := connect(ctx)
	if timestamp == 0 {
		klog.Exit("No -timestamp option supplied")
	}
	target := timestamp
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		exitWithDetails(err)
	}
	getEntry := func(idx int64) *ct.RawLogEntry {
		entries, err := logClient.GetRawEntries(ctx, idx, idx)
		if err != nil {
			exitWithDetails(err)
		}
		if l := len(entries.Entries); l != 1 {
			klog.Exitf("Unexpected number (%d) of entries received requesting index %d", l, idx)
		}
		logEntry, err := ct.RawLogEntryFromLeaf(idx, &entries.Entries[0])
		if err != nil {
			klog.Exitf("Failed to parse leaf %d: %v", idx, err)
		}
		return logEntry
	}
	// Performing a binary search assumes that the timestamps are monotonically
	// increasing.
	idx := sort.Search(int(sth.TreeSize), func(idx int) bool {
		klog.V(1).Infof("check timestamp at index %d", idx)
		entry := getEntry(int64(idx))
		return entry.Leaf.TimestampedEntry.Timestamp >= uint64(target)
	})
	when := ct.TimestampToTime(uint64(target))
	if idx >= int(sth.TreeSize) {
		fmt.Printf("No entry with timestamp>=%d (%v) found up to tree size %d\n", target, when, sth.TreeSize)
		return
	}
	fmt.Printf("First entry with timestamp>=%d (%v) found at index %d\n", target, when, idx)
	showRawLogEntry(getEntry(int64(idx)))
}
