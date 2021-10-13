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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/jsonclient"
	wh "github.com/google/certificate-transparency-go/witness/witness/client/http"
)

var (
	logURL   = flag.String("log_url", "", "The endpoint of the log HTTP API")
	logPK    = flag.String("log_pk", "", "A file containing the PEM-encoded log public key")
	logID    = flag.String("log_id", "", "The log ID")
	witness  = flag.String("witness_url", "", "The endpoint of the witness HTTP API")
	interval = flag.Duration("poll", 10*time.Second, "How quickly to poll the log to get updates")
)

type feeder struct {
	logID string
	wsth  *ct.SignedTreeHead
	c     *jsonclient.JSONClient
	w     wh.Witness
}

func main() {
	flag.Parse()
	ctx := context.Background()
	// Set up the witness client.
	if *logPK == "" {
		glog.Exit("--log_pk must not be empty")
	}
	var w wh.Witness
	pemPK, err := ioutil.ReadFile(*logPK)
	if err != nil {
		glog.Exitf("Failed to read public key from file: %v", err)
	}
	pk, _, _, err := ct.PublicKeyFromPEM(pemPK)
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
	// Now set up the log client.
	if *logID == "" {
		glog.Exit("--log_id must not be empty")
	}
	if *logURL == "" {
		glog.Exit("--log_url must not be empty")
	}
	opts := jsonclient.Options{PublicKey: string(pemPK)}
	c, err := jsonclient.New(*logURL, http.DefaultClient, opts)
	if err != nil {
		glog.Exitf("Failed to create JSON client: %v", err)
	}
	// Create the feeder with no initial witness STH.
	feeder := feeder{
		logID: *logID,
		c:     c,
		w:     w,
	}

	tik := time.NewTicker(*interval)
	for {
		wSize := feeder.latestSize()
		glog.V(2).Infof("Tick: start feedOnce (witness size %d)", wSize)
		if err := feeder.feedOnce(ctx); err != nil {
			glog.Warningf("Failed to feed: %v", err)
		}
		glog.V(2).Infof("Tick: feedOnce complete (witness size %d)", wSize)

		select {
		case <-ctx.Done():
			return
		case <-tik.C:
		}
	}
}

// latestSize returns the size of the latest witness STH held by the feeder.
func (f *feeder) latestSize() uint64 {
	if f.wsth != nil {
		return f.wsth.TreeSize
	}
	return 0
}

// feedOnce attempts to update the STH held by the witness to the latest STH
// provided by the log.
func (f *feeder) feedOnce(ctx context.Context) error {
	// Get and parse the latest STH from the log.
	var sthResp ct.GetSTHResponse
	_, csthRaw, err := f.c.GetAndParse(ctx, ct.GetSTHPath, nil, &sthResp)
	if err != nil {
		return fmt.Errorf("failed to get latest STH: %v", err)
	}
	csth, err := sthResp.ToSignedTreeHead()
	if err != nil {
		return fmt.Errorf("failed to parse response as STH: %v", err)
	}
	wSize := f.latestSize()
	if wSize >= csth.TreeSize {
		glog.V(1).Infof("Witness size %d >= log size %d - nothing to do", wSize, csth.TreeSize)
		return nil
	}

	glog.Infof("Updating witness from size %d to %d", wSize, csth.TreeSize)
	// If we want to update the witness then let's get a consistency proof.
	params := map[string]string{
		"first":  strconv.FormatUint(wSize, 10),
		"second": strconv.FormatUint(csth.TreeSize, 10),
	}
	var pfResp ct.GetSTHConsistencyResponse
	var pf [][]byte
	if wSize > 0 {
		if _, _, err := f.c.GetAndParse(ctx, ct.GetSTHConsistencyPath, params, &pfResp); err != nil {
			return fmt.Errorf("failed to get consistency proof: %v", err)
		}
		pf = pfResp.Consistency
	}
	// Now give the new STH and consistency proof to the witness.
	wsthRaw, err := f.w.Update(ctx, f.logID, csthRaw, pf)
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
	f.wsth = wsth
	return nil
}
