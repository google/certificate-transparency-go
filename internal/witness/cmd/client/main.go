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

// client fetches and verifies new STHs for a set of logs from a single witness.
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	wit_api "github.com/google/certificate-transparency-go/internal/witness/api"
	wh "github.com/google/certificate-transparency-go/internal/witness/client/http"
	"github.com/google/certificate-transparency-go/internal/witness/verifier"
	"github.com/google/certificate-transparency-go/loglist3"
	"k8s.io/klog/v2"
)

var (
	logList   = flag.String("log_list_url", "https://www.gstatic.com/ct/log_list/v3/log_list.json", "The location of the log list")
	witness   = flag.String("witness_url", "", "The endpoint of the witness HTTP API")
	witnessPK = flag.String("witness_pk", "", "The base64-encoded witness public key")
	interval  = flag.Duration("poll", 10*time.Second, "How frequently to poll to get new witnessed STHs")
)

// WitnessSigVerifier verifies the witness' signature on a cosigned STH.
type WitnessSigVerifier interface {
	VerifySignature(cosigned wit_api.CosignedSTH) error
}

// Witness consists of the witness' URL and signature verifier.
type Witness struct {
	Client   *wh.Witness
	Verifier WitnessSigVerifier
}

type ctLog struct {
	id       string
	name     string
	wsth     *wit_api.CosignedSTH
	verifier *ct.SignatureVerifier
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if *witness == "" {
		klog.Exit("--witness_url must not be empty")
	}
	if *witnessPK == "" {
		klog.Exit("--witness_pk must not be empty")
	}
	ctx := context.Background()
	// Set up the witness client.
	wURL, err := url.Parse(*witness)
	if err != nil {
		klog.Exitf("Failed to parse witness URL: %v", err)
	}
	pk, err := ct.PublicKeyFromB64(*witnessPK)
	if err != nil {
		klog.Exitf("Failed to create witness public key: %v", err)
	}
	wv, err := verifier.NewWitnessVerifier(pk)
	if err != nil {
		klog.Exitf("Failed to create witness signature verifier: %v", err)
	}
	w := Witness{
		Client: &wh.Witness{
			URL: wURL,
		},
		Verifier: wv,
	}
	// Set up the log data.
	ctLogs, err := populateLogs(*logList)
	if err != nil {
		klog.Exitf("Failed to set up log data: %v", err)
	}
	// Now poll the witness for each log.
	wg := &sync.WaitGroup{}
	for _, log := range ctLogs {
		wg.Add(1)
		go func(witness *Witness, log ctLog) {
			defer wg.Done()
			if err := log.getSTH(ctx, witness, *interval); err != nil {
				klog.Errorf("getSTH: %v", err)
			}
		}(&w, log)
	}
	wg.Wait()
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
			//logPK := base64.StdEncoding.EncodeToString(log.Key)
			//pk, err := ct.PublicKeyFromB64(logPK)
			pk, err := x509.ParsePKIXPublicKey(log.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to create public key for %s: %v", log.Description, err)
			}
			v, err := ct.NewSignatureVerifier(pk)
			if err != nil {
				return nil, fmt.Errorf("failed to create signature verifier: %v", err)
			}
			l := ctLog{
				id:       logID,
				name:     log.Description,
				verifier: v,
			}
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// getSTH gets cosigned STHs for a given log continuously from the witness,
// returning only when the context is done.
func (l *ctLog) getSTH(ctx context.Context, witness *Witness, interval time.Duration) error {
	tik := time.NewTicker(interval)
	defer tik.Stop()
	for {
		func() {
			ctx, cancel := context.WithTimeout(ctx, interval)
			defer cancel()

			klog.V(2).Infof("Requesting STH for %s from witness", l.name)
			if err := l.getOnce(ctx, witness); err != nil {
				klog.Warningf("Failed to retrieve STH for %s: %v", l.name, err)
			} else {
				klog.Infof("Verified the STH for %s at size %d!", l.name, l.wsth.TreeSize)
			}
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tik.C:
		}
	}
}

// getOnce gets a new cosigned STH once and verifies it, replacing the stored STH
// in the case that it does verify.
func (l *ctLog) getOnce(ctx context.Context, witness *Witness) error {
	// Get and parse the latest cosigned STH from the witness.
	var cSTH wit_api.CosignedSTH
	sthRaw, err := witness.Client.GetLatestSTH(ctx, l.id)
	if err != nil {
		return fmt.Errorf("failed to get STH: %v", err)
	}
	if err := json.Unmarshal(sthRaw, &cSTH); err != nil {
		return fmt.Errorf("failed to unmarshal STH: %v", err)
	}
	// First verify the witness signature(s).
	if err := witness.Verifier.VerifySignature(cSTH); err != nil {
		return fmt.Errorf("failed to verify witness signature: %v", err)
	}
	// Then verify the log signature.
	plainSTH := cSTH.SignedTreeHead
	if err := l.verifier.VerifySTHSignature(plainSTH); err != nil {
		return fmt.Errorf("failed to verify log signature: %v", err)
	}
	l.wsth = &cSTH
	return nil
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
