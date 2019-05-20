// Copyright 2019 Google Inc. All Rights Reserved.
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

// Hammer tool sends multiple add-pre-chain requests to Submission proxy at the same time.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/submission"
)

// Default number of submissions is explicitly low.
// After several runs, likely to hit Log rate-limits.
var (
	proxyEndpoint = flag.String("proxy_endpoint", "http://localhost:5951/", "Endpoint for HTTP (host:port)")
	timeout       = flag.Duration("duration", 0*time.Minute, "Time to run continuous flow of submissions")
	count         = flag.Int("count", 1, "Total number of submissions to execute")
	qps           = flag.Int("qps", 5, "Number of requests per second")
)

func main() {
	wd, _ := os.Getwd()
	certData, err := ioutil.ReadFile(wd + "/submission/hammer/testdata/precert.der")
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	interimData, err := ioutil.ReadFile(wd + "/submission/hammer/testdata/interim.der")
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	var req ct.AddChainRequest
	req.Chain = append(req.Chain, certData)
	req.Chain = append(req.Chain, interimData)

	postBody, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// Submission runs until timeout or count is reached. If any of those flags
	// is set to 0, only other flag value is used as restriction.
	ctx, cancel := context.WithCancel(context.Background())
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), *timeout)
	} else if *count <= 0 {
		// Both restrictions set to 0. Nothing to run.
		return
	}

	ticker := time.NewTicker(time.Second)
	leftToSend := *count
	leftToReceive := *count
	mu := sync.Mutex{}
	// If count flag is not set, send *qps requests each second until *timeout.
	if *count <= 0 {
		leftToSend = int(*timeout / time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			batchSize := *qps
			if leftToSend < *qps {
				batchSize = leftToSend
			}
			leftToSend -= batchSize
			for i := 0; i < batchSize; i++ {
				fmt.Printf("%v\n", i)
				go func() {
					resp, err := http.Post(*proxyEndpoint+"ct/v1/proxy/add-pre-chain/", "application/json", bytes.NewBuffer(postBody))
					if err != nil {
						log.Fatalf("http.Post(add-pre-chain)=(_,%q); want (_,nil)", err)
					}
					var scts submission.SCTBatch
					err = json.NewDecoder(resp.Body).Decode(&scts)
					if err != nil {
						log.Fatalf("Unable to decode response %v\n", err)
					}
					fmt.Printf("%v\n", scts)
					mu.Lock()
					defer mu.Unlock()
					leftToReceive--
					if leftToReceive == 0 {
						cancel()
					}
				}()
			}
		}
	}
}
