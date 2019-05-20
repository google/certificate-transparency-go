// Package main sends multiple add-pre-chain requests to Submission proxy at the same time.
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
	left_to_send := *count
	left_to_receive := *count
	mu := sync.Mutex{}
	// If count flag is not set, send *qps requests each second until *timeout.
	if *count <= 0 {
		left_to_send = int(*timeout / time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			batch_size := *qps
			if left_to_send < *qps {
				batch_size = left_to_send
			}
			left_to_send -= batch_size
			for i := 0; i < batch_size; i++ {
				fmt.Printf("%v\n", i)
				go func() {
					resp, err := http.Post(*proxyEndpoint+"ct/v1/proxy/add-pre-chain/", "application/json", bytes.NewBuffer(postBody))
					if err != nil {
						log.Fatalf("http.Post(add-pre-chain)=(_,%q); want (_,nil)", err)
					}
					var scts submission.SCTBatch
					err = json.NewDecoder(resp.Body).Decode(&scts)
					if err != nil  {
						log.Fatalf("Unable to decode response %v\n", err)
					}
					fmt.Printf("%v\n", scts)
					mu.Lock()
					defer mu.Unlock()
					left_to_receive -= 1
					if left_to_receive == 0 {
						cancel()
					}
				}()
			}
		}
	}
}
