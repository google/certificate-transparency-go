// Copyright 2019 Google LLC. All Rights Reserved.
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
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/submission"
)

// Default number of submissions is intentionally low.
// After several runs, likely to hit Log rate-limits.
var (
	proxyEndpoint = flag.String("proxy_endpoint", "http://localhost:5951/", "Endpoint for HTTP (host:port). Final slash is expected")
	timeout       = flag.Duration("duration", 0*time.Minute, "Time to run continuous flow of submissions. "+
		"When this and --count both have non-zero values, submission ends upon reaching earliest restriction")
	count = flag.Int("count", 10, "Total number of submissions to execute. "+
		"When this and --duration both have non-zero values, submission ends upon reaching earliest restriction")
	qps = flag.Int("qps", 5, "Number of requests per second")
)

func main() {
	flag.Parse()
	certData, err := os.ReadFile("submission/hammer/testdata/precert.der")
	if err != nil {
		log.Fatal(err)
	}
	interimData, err := os.ReadFile("submission/hammer/testdata/intermediate.der")
	if err != nil {
		log.Fatal(err)
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
		log.Print("Both timeout and count flags set to 0. No submissions to be sent.")
		return
	}

	leftToSend := *count
	// If count flag is not set, send *qps requests each second until *timeout.
	if *count <= 0 {
		leftToSend = int(*timeout/time.Second) * *qps
	}
	var batchSize int

	schedule.Every(ctx, time.Second, func(ctx context.Context) {
		batchSize = *qps
		if leftToSend < *qps {
			batchSize = leftToSend
		}
		leftToSend -= batchSize
		if batchSize == 0 {
			cancel()
		}
		var wg sync.WaitGroup
		wg.Add(batchSize)
		for i := 0; i < batchSize; i++ {
			go func() {
				url := *proxyEndpoint + "ct/v1/proxy/add-pre-chain/"
				resp, err := http.Post(url, "application/json", bytes.NewBuffer(postBody))
				if err != nil {
					log.Fatalf("http.Post(%s)=(_,%q); want (_,nil)", url, err)
				}
				defer resp.Body.Close()
				var scts submission.SCTBatch
				err = json.NewDecoder(resp.Body).Decode(&scts)
				if err != nil {
					responseData, err := io.ReadAll(resp.Body)
					if err != nil {
						log.Fatalf("Unable to parse response: %v", err)
					}
					log.Fatalf("Unable to decode response: %v\n%v", err, responseData)
				}
				fmt.Printf("%v\n", scts)
				wg.Done()
			}()
		}
		wg.Wait()
	})
}
