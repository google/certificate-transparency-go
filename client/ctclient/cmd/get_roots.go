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

	"github.com/spf13/cobra"
)

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("get-roots %s", connectionFlags),
		Aliases: []string{"getroots", "roots"},
		Short:   "Fetch the root certificates accepted by the log",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runGetRoots(cmd.Context())
		},
	}
	// TODO(pavelkalinnikov): Don't share this parameter with get-entries.
	cmd.Flags().BoolVar(&textOut, "text", true, "Display certificates as text")
	rootCmd.AddCommand(&cmd)
}

// runGetRoots runs the get-roots command.
func runGetRoots(ctx context.Context) {
	logClient := connect(ctx)
	roots, err := logClient.GetAcceptedRoots(ctx)
	if err != nil {
		exitWithDetails(err)
	}
	for _, root := range roots {
		showRawCert(root)
	}
}
