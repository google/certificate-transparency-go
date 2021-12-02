// Copyright 2021 Google LLC. All Rights Reserved.
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

// feeder polls the sumdb log and pushes the results to a generic witness.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	wh "github.com/google/certificate-transparency-go/internal/witness/client/http"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist2"
)

var (
	logList  = flag.String("log_list_url", "https://www.gstatic.com/ct/log_list/v3/log_list.json", "The location of the log list")
	witness  = flag.String("witness_url", "", "The endpoint of the witness HTTP API")
	interval = flag.Duration("poll", 10*time.Second, "How quickly to poll the log to get updates")
)

// feeder contains a map from log IDs to logData and a witness client.
type feeder struct {
	logs map[string]logData
	//logID string
	//wsth  *ct.SignedTreeHead
	//c     *client.LogClient
	w    wh.Witness
}

// logData contains the latest witnessed STH for a log and a log client.
type logData struct {
	wsth   *ct.SignedTreeHead
	client *client.LogClient
}

// setupLogs populates the feeder's logs map based on the logList.
func populateLogs(logListURL string) (map[string]logData, error) {
	resp, err := http.Get(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve log list: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist2.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	logs := make(map[string]logData)
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if log.State.LogStatus() == loglist2.UsableLogStatus {
				c, err := createLogClient(string(log.Key), log.URL)
				if err != nil {
					return nil, fmt.Errorf("failed to create log client: %v", err)
				}
				logs[string(log.LogID)] = logData{
				    client : c,
				}
			}
		}
	}
	return logs, nil
}

func createLogClient(key string, url string) (*client.LogClient, error) {
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		glog.Exitf("Failed to decode public key: %v", err)
	}
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK)}
	c, err := client.New(url, http.DefaultClient, opts)
	if err != nil {
		glog.Exitf("Failed to create JSON client: %v", err)
	}
	return c, nil
}

func main() {
	flag.Parse()
	ctx := context.Background()
	// Set up the witness client.
	if *logPK == "" {
		glog.Exit("--log_pk must not be empty")
	}
	var w wh.Witness
	pk, err := ct.PublicKeyFromB64(*logPK)
	if err != nil {
		glog.Exitf("Failed to create public key: %v", err)
	}
	sv, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		glog.Exitf("Failed to create signature verifier: %v", err)
	}
	if wURL, err := url.Parse(*witness); err != nil {
		glog.Exitf("Failed to parse witness URL: %v", err)
	} else {
		w = wh.Witness{
			URL:      wURL,
			Verifier: *sv,
		}
	}
	// Now set up the log data (with no initial witness STH).
	logData, err := populateLogs(*logList)
	if err != nil {
		glog.Exitf("Failed to set up log data: %v", err)
	}
	// Create the feeder.
	feeder := feeder{
		logs:  logData,
		w:     w,
	}
	// Now feed each log one by one.
	tik := time.NewTicker(*interval)
	for {
		for id := range feeder.logs {
			wSize := feeder.latestSize(id)
			glog.V(2).Infof("Tick: start feedOnce for log %s (witness size %d)", id, wSize)
			if err := feeder.feedOnce(ctx, id); err != nil {
				glog.Warningf("Failed to feed for %s: %v", id, err)
			}
			glog.V(2).Infof("Tick: feedOnce complete for %s (witness size %d)", id, wSize)

			select {
			case <-ctx.Done():
				return
			case <-tik.C:
			}
		}
	}
}

// latestSize returns the size of the latest witness STH held by the feeder for
// a given logID.
func (f *feeder) latestSize(logID string) uint64 {
	ld, ok := f.logs[logID]
	if !ok {
		return 0
	}
	if ld.wsth != nil {
		return ld.wsth.TreeSize
	}
	return 0
}

// feedOnce attempts to update the STH held by the witness to the latest STH
// provided by the log identified by logID.
func (f *feeder) feedOnce(ctx context.Context, logID string) error {
	ld, ok := f.logs[logID]
	if !ok {
		return fmt.Errorf("no log found for %s", logID)
	}
	// Get and parse the latest STH from the log.
	var sthResp ct.GetSTHResponse
	_, csthRaw, err := ld.client.GetAndParse(ctx, ct.GetSTHPath, nil, &sthResp)
	if err != nil {
		return fmt.Errorf("failed to get latest STH: %v", err)
	}
	csth, err := sthResp.ToSignedTreeHead()
	if err != nil {
		return fmt.Errorf("failed to parse response as STH: %v", err)
	}
	wSize := f.latestSize(logID)
	if wSize >= csth.TreeSize {
		glog.V(1).Infof("Witness size %d >= log size %d for log %s - nothing to do", wSize, csth.TreeSize, logID)
		return nil
	}

	glog.Infof("Updating witness from size %d to %d for log %s", wSize, csth.TreeSize, logID)
	// If we want to update the witness then let's get a consistency proof.
	var pf [][]byte
	if wSize > 0 {
		pf, err = ld.client.GetSTHConsistency(ctx, wSize, csth.TreeSize)
		if err != nil {
			return fmt.Errorf("failed to get consistency proof: %v", err)
		}
	}
	// Now give the new STH and consistency proof to the witness.
	wsthRaw, err := f.w.Update(ctx, logID, csthRaw, pf)
	if err != nil && !errors.Is(err, wh.ErrSTHTooOld) {
		return fmt.Errorf("failed to update STH: %v", err)
	}
	// Parse the STH it returns.
	var wsthJSON ct.GetSTHResponse
	if err := json.Unmarshal(wsthRaw, &wsthJSON); err != nil {
		return fmt.Errorf("failed to unmarshal json: %v", err)
	}
	wsth, err := wsthJSON.ToSignedTreeHead()
	if err != nil {
		return fmt.Errorf("failed to create STH: %v", err)
	}
	// For now just update our local state with whatever the witness
	// returns, even if we got wh.ErrSTHTooOld.  This is fine if we're the
	// only feeder for this witness.
	f.logs[logID] = logData{
		wsth:   wsth,
		client: ld.client,
	}
	return nil
}
