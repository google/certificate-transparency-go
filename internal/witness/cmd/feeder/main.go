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
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	wh "github.com/google/certificate-transparency-go/internal/witness/client/http"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"k8s.io/klog/v2"
)

var (
	logList  = flag.String("log_list_url", "https://www.gstatic.com/ct/log_list/v3/log_list.json", "The location of the log list")
	witness  = flag.String("witness_url", "", "The endpoint of the witness HTTP API")
	interval = flag.Duration("poll", 10*time.Second, "How quickly to poll the log to get updates")
)

// ctLog contains the latest witnessed STH for a log and a log client.
type ctLog struct {
	id     string
	name   string
	wsth   *ct.SignedTreeHead
	client *client.LogClient
}

// populateLogs populates a list of ctLogs based on the log list.
func populateLogs(logListURL string) ([]ctLog, error) {
	u, err := url.Parse(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get log list data: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	var logs []ctLog
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			logID := base64.StdEncoding.EncodeToString(log.LogID)
			c, err := createLogClient(log.Key, log.URL)
			if err != nil {
				return nil, fmt.Errorf("failed to create log client: %v", err)
			}
			l := ctLog{
				id:     logID,
				name:   log.Description,
				client: c,
			}
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// createLogClient creates a CT log client from a public key and URL.
func createLogClient(key []byte, url string) (*client.LogClient, error) {
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK)}
	c, err := client.New(url, http.DefaultClient, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON client: %v", err)
	}
	return c, nil
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if *witness == "" {
		klog.Exit("--witness_url must not be empty")
	}
	ctx := context.Background()
	// Set up the witness client.
	var w wh.Witness
	if wURL, err := url.Parse(*witness); err != nil {
		klog.Exitf("Failed to parse witness URL: %v", err)
	} else {
		w = wh.Witness{
			URL: wURL,
		}
	}
	// Now set up the log data (with no initial witness STH).
	ctLogs, err := populateLogs(*logList)
	if err != nil {
		klog.Exitf("Failed to set up log data: %v", err)
	}
	// Now feed each log.
	wg := &sync.WaitGroup{}
	for _, log := range ctLogs {
		wg.Add(1)
		go func(witness *wh.Witness, log ctLog) {
			defer wg.Done()
			if err := log.feed(ctx, witness, *interval); err != nil {
				klog.Errorf("feedLog: %v", err)
			}
		}(&w, log)
	}
	wg.Wait()
}

// feed feeds continuously for a given log, returning only when the context
// is done.
func (l *ctLog) feed(ctx context.Context, witness *wh.Witness, interval time.Duration) error {
	tik := time.NewTicker(interval)
	defer tik.Stop()
	for {
		func() {
			ctx, cancel := context.WithTimeout(ctx, interval)
			defer cancel()

			klog.V(2).Infof("Start feedOnce for %s", l.name)
			if err := l.feedOnce(ctx, witness); err != nil {
				klog.Warningf("Failed to feed for %s: %v", l.name, err)
			}
			klog.V(2).Infof("feedOnce complete for %s", l.name)
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tik.C:
		}
	}
}

// feedOnce attempts to update the STH held by the witness to the latest STH
// provided by the log.
func (l *ctLog) feedOnce(ctx context.Context, w *wh.Witness) error {
	// Get and parse the latest STH from the log.
	var sthResp ct.GetSTHResponse
	_, csthRaw, err := l.client.GetAndParse(ctx, ct.GetSTHPath, nil, &sthResp)
	if err != nil {
		return fmt.Errorf("failed to get latest STH: %v", err)
	}
	csth, err := sthResp.ToSignedTreeHead()
	if err != nil {
		return fmt.Errorf("failed to parse response as STH: %v", err)
	}
	wSize, err := l.latestSize(ctx, w)
	if err != nil {
		return fmt.Errorf("failed to get latest size for %s: %v", l.name, err)
	}
	if wSize >= csth.TreeSize {
		klog.V(1).Infof("Witness size %d >= log size %d for %s - nothing to do", wSize, csth.TreeSize, l.name)
		return nil
	}

	klog.Infof("Updating witness from size %d to %d for %s", wSize, csth.TreeSize, l.name)
	// If we want to update the witness then let's get a consistency proof.
	var pf [][]byte
	if wSize > 0 {
		pf, err = l.client.GetSTHConsistency(ctx, wSize, csth.TreeSize)
		if err != nil {
			return fmt.Errorf("failed to get consistency proof: %v", err)
		}
	}
	// Now give the new STH and consistency proof to the witness.
	wsthRaw, err := w.Update(ctx, l.id, csthRaw, pf)
	if err != nil && !errors.Is(err, wh.ErrSTHTooOld) {
		return fmt.Errorf("failed to update STH: %v", err)
	}
	if errors.Is(err, wh.ErrSTHTooOld) {
		klog.Infof("STH mismatch at log size %d for %s", wSize, l.name)
		klog.Infof("%s", wsthRaw)
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
	l.wsth = wsth
	return nil
}

// latestSize returns the size of the latest witness STH.  If this is nil then
// it first checks with the witness to see if it has anything stored before
// returning 0.
func (l *ctLog) latestSize(ctx context.Context, w *wh.Witness) (uint64, error) {
	if l.wsth != nil {
		return l.wsth.TreeSize, nil
	}
	wsthRaw, err := w.GetLatestSTH(ctx, l.id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If the witness has no stored STH then 0 is the correct size.
			return 0, nil
		}
		return 0, err
	}
	var wsthJSON ct.GetSTHResponse
	if err := json.Unmarshal(wsthRaw, &wsthJSON); err != nil {
		return 0, fmt.Errorf("failed to unmarshal json: %v", err)
	}
	wsth, err := wsthJSON.ToSignedTreeHead()
	if err != nil {
		return 0, fmt.Errorf("failed to create STH: %v", err)
	}
	l.wsth = wsth
	return wsth.TreeSize, nil
}

var getByScheme = map[string]func(*url.URL) ([]byte, error){
	"http":  readHTTP,
	"https": readHTTP,
	"file": func(u *url.URL) ([]byte, error) {
		return os.ReadFile(u.Path)
	},
}

// readHTTP fetches and reads data from an HTTP-based URL.
func readHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// readURL fetches and reads data from an HTTP-based or filesystem URL.
func readURL(u *url.URL) ([]byte, error) {
	s := u.Scheme
	queryFn, ok := getByScheme[s]
	if !ok {
		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
	}
	return queryFn(u)
}
