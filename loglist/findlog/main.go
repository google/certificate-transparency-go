// Copyright 2018 Google Inc. All Rights Reserved.
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

// The findlog binary attempts to provide information about a log based on
// ID or name.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	logList = flag.String("log_list", loglist.LogListURL, "Location of master log list (URL or filename)")
	verbose = flag.Bool("verbose", false, "Print more information")
)

func main() {
	flag.Parse()
	client := &http.Client{Timeout: time.Second * 10}

	llData, err := x509util.ReadFileOrURL(*logList, client)
	if err != nil {
		glog.Exitf("Failed to read log list: %v", err)
	}
	var ll loglist.LogList
	if err = json.Unmarshal(llData, &ll); err != nil {
		glog.Exitf("Failed to parse log list: %v", err)
	}

	args := flag.Args()
	if len(args) == 0 {
		glog.Exitf("No logs specified")
	}
	for _, arg := range args {
		logs := ll.FuzzyFindLog(arg)
		for _, log := range logs {
			fmt.Printf("%s \t\t<%s>\n", log.Description, log.URL)
			if *verbose {
				fmt.Printf("    Key (hex):    %x\n", log.Key)
				fmt.Printf("    Key (base64): %s\n", base64.StdEncoding.EncodeToString(log.Key))
				keyhash := sha256.Sum256(log.Key)
				fmt.Printf("    KeyHash (hex):    %x\n", keyhash[:])
				fmt.Printf("    KeyHash (base64): %s\n", base64.StdEncoding.EncodeToString(keyhash[:]))
				fmt.Printf("    MMD: %d seconds\n", log.MaximumMergeDelay)
				for _, who := range log.OperatedBy {
					for _, op := range ll.Operators {
						if op.ID == who {
							fmt.Printf("    Operator: %s\n", op.Name)
						}
					}
				}
				if log.FinalSTH != nil {
					fmt.Printf("    FinalSTH:\n")
					fmt.Printf("        TreeSize: %d\n", log.FinalSTH.TreeSize)
					when := ct.TimestampToTime(uint64(log.FinalSTH.Timestamp))
					fmt.Printf("        Timestamp: %d (%v)\n", log.FinalSTH.Timestamp, when)
					fmt.Printf("        SHA256RootHash: %x\n", log.FinalSTH.SHA256RootHash)
					fmt.Printf("        TreeHeadSignature: %x\n", log.FinalSTH.TreeHeadSignature)
				}
				if log.DisqualifiedAt > 0 {
					when := ct.TimestampToTime(uint64(log.DisqualifiedAt))
					fmt.Printf("    Disqualified at: %v (%d)\n", when, log.DisqualifiedAt)
				}
				if log.DNSAPIEndpoint != "" {
					fmt.Printf("    DNS API endpoint: %s\n", log.DNSAPIEndpoint)
				}
			}
		}
	}
}
