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
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/loglist"
)

var (
	logList = flag.String("log_list", loglist.LogListURL, "Location of master log list (URL or filename)")
	verbose = flag.Bool("verbose", false, "Print more information")
)

func readPossibleURL(target string) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ioutil.ReadFile(target)
	}

	client := http.Client{Timeout: time.Second * 10}
	rsp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to http.Get(%q): %v", target, err)
	}
	return ioutil.ReadAll(rsp.Body)
}

func ctTimestampToTime(ts int) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

func main() {
	flag.Parse()

	llData, err := readPossibleURL(*logList)
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
					when := ctTimestampToTime(log.FinalSTH.Timestamp)
					fmt.Printf("        Timestamp: %d (%v)\n", log.FinalSTH.Timestamp, when)
					fmt.Printf("        SHA256RootHash: %x\n", log.FinalSTH.SHA256RootHash)
					fmt.Printf("        TreeHeadSignature: %x\n", log.FinalSTH.TreeHeadSignature)
				}
				if log.DisqualifiedAt > 0 {
					when := ctTimestampToTime(log.DisqualifiedAt)
					fmt.Printf("    Disqualified at: %v (%d)\n", when, log.DisqualifiedAt)
				}
				if log.DNSAPIEndpoint != "" {
					fmt.Printf("    DNS API endpoint: %s\n", log.DNSAPIEndpoint)
				}
			}
		}
	}
}
