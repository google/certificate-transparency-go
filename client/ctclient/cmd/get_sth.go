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

	ct "github.com/google/certificate-transparency-go"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     fmt.Sprintf("get-sth %s", connectionFlags),
		Aliases: []string{"sth"},
		Short:   "Fetch the latest STH of the log",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runGetSTH(cmd.Context())
		},
	})
}

// runGetSTH runs the get-sth command.
func runGetSTH(ctx context.Context) {
	logClient := connect(ctx)
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		exitWithDetails(err)
	}
	// Display the STH.
	when := ct.TimestampToTime(sth.Timestamp)
	fmt.Printf("%v (timestamp %d): Got STH for %v log (size=%d) at %v, hash %x\n", when, sth.Timestamp, sth.Version, sth.TreeSize, logClient.BaseURI(), sth.SHA256RootHash)
	fmt.Printf("%v\n", signatureToString(&sth.TreeHeadSignature))
}
