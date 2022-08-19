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

package http

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/internal/witness/api"
	"github.com/google/certificate-transparency-go/internal/witness/cmd/witness/internal/witness"
	"github.com/gorilla/mux"

	_ "github.com/mattn/go-sqlite3" // Load drivers for sqlite3
)

var (
	// https://play.golang.org/p/gCY2Zi2BJ8G to generate keys and
	// https://play.golang.org/p/KUXRShKdYTb to sign things with loaded keys.
	mSK = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIECRHc4ORynd+lpqWYmjCIAmDjyLEJZSuvv4KdcIi+hEoAoGCCqGSM49
AwEHoUQDQgAEn1Ahe5/kYQgqYk1kSzp0ZCvL1Cf/tOZ+GUrGjNC0CrTqSylMuU1f
AcWDaKYB/Yr3fq/5lNqJBRjsOnI4KkaEtw==
-----END EC PRIVATE KEY-----`
	mPK = mustCreatePK(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn1Ahe5/kYQgqYk1kSzp0ZCvL1Cf/
tOZ+GUrGjNC0CrTqSylMuU1fAcWDaKYB/Yr3fq/5lNqJBRjsOnI4KkaEtw==
-----END PUBLIC KEY-----`)
	mID = "fRThG/6Ymon8NnpRMQJIgCMgjtrBVnOidYenOB0n6FI="
	bSK = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIICRst6QhwffAkeOQGIhcCSmB7/LYQXevwrv8TD9FjU7oAoGCCqGSM49
AwEHoUQDQgAE5FTw9vYXDEFiZb9kS1LV7GzU1Mo/xQ8D2Vnkl7WqNTB2kJ45aTtl
F2bBk8i50oWNRlRLyi5MVl7j+6LVhMiBeA==
-----END EC PRIVATE KEY-----`
	bPK = mustCreatePK(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5FTw9vYXDEFiZb9kS1LV7GzU1Mo/
xQ8D2Vnkl7WqNTB2kJ45aTtlF2bBk8i50oWNRlRLyi5MVl7j+6LVhMiBeA==
-----END PUBLIC KEY-----`)
	bID = "CwWwEY4IKzy1bfZ6QW0IU9mky0ruOQvzWOYkmRGMVP4="
	wSK = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+/pzQGPt88nmVlMC
CjHXGLH93bZ5ZkLVTjsHLi2UQiKhRANCAAQ2DYOW5eMnGcMCDtfK7aFIJg0JBKIZ
cx8fz81azP6v6s8oYMyU5e5bYAfgm1RjGvjC2YTLqCpMvSIeK+rudqg4
-----END PRIVATE KEY-----`
	wPK = mustCreatePK(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENg2DluXjJxnDAg7Xyu2hSCYNCQSi
GXMfH8/NWsz+r+rPKGDMlOXuW2AH4JtUYxr4wtmEy6gqTL0iHivq7naoOA==
-----END PUBLIC KEY-----`)
	mInit     = []byte(`{"tree_size":5,"timestamp":0,"sha256_root_hash":"41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=","tree_head_signature":"BAMARzBFAiEA4CEXH2Z+T4Rcj3YTvgK5qM9NuFYHipI13Il6A/ozTFUCIBDY1VDFy8ZezXsuWNs+iLzkyO5I5kCZldGeMvspHOof"}`)
	bInit     = []byte(`{"tree_size":5,"timestamp":0,"sha256_root_hash":"41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=","tree_head_signature":"BAMASDBGAiEAjSUy1d7/n1MOYWCnx2DzU3nQk1OUHzRtFJl+eDCquBsCIQDEG2vk1A+LmHZfyt/BN4by2324rxWFFzAeG1f2EyXk9w=="}`)
	mNext     = []byte(`{"tree_size":8,"timestamp":1,"sha256_root_hash":"V8K9aklZ4EPB+RMOk1/8VsJUdFZR77GDtZUQq84vSbo=","tree_head_signature":"BAMARjBEAiB9SZfr3JJbLsSE4mhnHE9hbcbu97nsbKcONnXeJXeigwIgJTWVh5FLNfUre5uCRLY4B1KEyS8tcGbaaHdEMk2WAmc="}`)
	consProof = [][]byte{
		dh("b9e1d62618f7fee8034e4c5010f727ab24d8e4705cb296c374bf2025a87a10d2", 32),
		dh("aac66cd7a79ce4012d80762fe8eec3a77f22d1ca4145c3f4cee022e7efcd599d", 32),
		dh("89d0f753f66a290c483b39cd5e9eafb12021293395fad3d4a2ad053cfbcfdc9e", 32),
		dh("29e40bb79c966f4c6fe96aff6f30acfce5f3e8d84c02215175d6e018a5dee833", 32),
	}
	_ = mSK
	_ = bSK
	_ = wPK
)

type logOpts struct {
	ID string
	PK crypto.PublicKey
}

func newWitness(t *testing.T, d *sql.DB, logs []logOpts) *witness.Witness {
	// Set up Opts for the witness.
	logMap := make(map[string]ct.SignatureVerifier)
	for _, log := range logs {
		logV, err := ct.NewSignatureVerifier(log.PK)
		if err != nil {
			t.Fatalf("couldn't create a log verifier: %v", err)
		}
		logMap[log.ID] = *logV
	}
	opts := witness.Opts{
		DB:        d,
		PrivKey:   wSK,
		KnownLogs: logMap,
	}
	// Create the witness
	w, err := witness.New(opts)
	if err != nil {
		t.Fatalf("couldn't create witness: %v", err)
	}
	return w
}

func dh(h string, expLen int) []byte {
	r, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if got := len(r); got != expLen {
		panic(fmt.Sprintf("decode %q: len=%d, want %d", h, got, expLen))
	}
	return r
}

func mustCreateDB(t *testing.T) (*sql.DB, func() error) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open temporary in-memory DB: %v", err)
	}
	return db, db.Close
}

func mustCreatePK(pkPem string) crypto.PublicKey {
	pk, _, _, err := ct.PublicKeyFromPEM([]byte(pkPem))
	if err != nil {
		panic(err)
	}
	return pk
}

func createTestEnv(w *witness.Witness) (*httptest.Server, func()) {
	r := mux.NewRouter().UseEncodedPath()
	server := NewServer(w)
	server.RegisterHandlers(r)
	ts := httptest.NewServer(r)
	return ts, ts.Close
}

func TestGetLogs(t *testing.T) {
	for _, test := range []struct {
		desc       string
		logIDs     []string
		logPKs     []crypto.PublicKey
		sths       [][]byte
		wantStatus int
		wantBody   []string
	}{
		{
			desc:       "no logs",
			logIDs:     []string{},
			wantStatus: http.StatusOK,
			wantBody:   []string{},
		}, {
			desc:       "one log",
			logIDs:     []string{mID},
			logPKs:     []crypto.PublicKey{mPK},
			sths:       [][]byte{mInit},
			wantStatus: http.StatusOK,
			wantBody:   []string{mID},
		}, {
			desc:       "two logs",
			logIDs:     []string{bID, mID},
			logPKs:     []crypto.PublicKey{bPK, mPK},
			sths:       [][]byte{bInit, mInit},
			wantStatus: http.StatusOK,
			wantBody:   []string{bID, mID},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			d, closeFn := mustCreateDB(t)
			defer closeFn()
			ctx := context.Background()
			// Set up witness and give it some STHs.
			logs := make([]logOpts, len(test.logIDs))
			for i, logID := range test.logIDs {
				logs[i] = logOpts{ID: logID,
					PK: test.logPKs[i],
				}
			}
			w := newWitness(t, d, logs)
			for i, logID := range test.logIDs {
				if _, err := w.Update(ctx, logID, test.sths[i], nil); err != nil {
					t.Errorf("failed to set STH: %v", err)
				}
			}
			// Now set up the http server.
			ts, tsCloseFn := createTestEnv(w)
			defer tsCloseFn()
			client := ts.Client()
			url := fmt.Sprintf("%s%s", ts.URL, api.HTTPGetLogs)
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("error response: %v", err)
			}
			if got, want := resp.StatusCode, test.wantStatus; got != want {
				t.Errorf("status code got %d, want %d", got, want)
			}
			if len(test.wantBody) > 0 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read body: %v", err)
				}
				var logs []string
				if err := json.Unmarshal(body, &logs); err != nil {
					t.Fatalf("failed to unmarshal body: %v", err)
				}
				if len(logs) != len(test.wantBody) {
					t.Fatalf("got %d logs, want %d", len(logs), len(test.wantBody))
				}
				sort.Strings(logs)
				for i := range logs {
					if logs[i] != test.wantBody[i] {
						t.Fatalf("got %q, want %q", logs[i], test.wantBody[i])
					}
				}
			}
		})
	}
}

func TestGetChkpt(t *testing.T) {
	for _, test := range []struct {
		desc       string
		setID      string
		setPK      crypto.PublicKey
		queryID    string
		queryPK    crypto.PublicKey
		sth        []byte
		wantStatus int
	}{
		{
			desc:       "happy path",
			setID:      mID,
			setPK:      mPK,
			queryID:    mID,
			queryPK:    mPK,
			sth:        mInit,
			wantStatus: http.StatusOK,
		}, {
			desc:       "other log",
			setID:      mID,
			setPK:      mPK,
			queryID:    bID,
			sth:        mInit,
			wantStatus: http.StatusNotFound,
		}, {
			desc:       "nothing there",
			setID:      mID,
			setPK:      mPK,
			queryID:    mID,
			sth:        nil,
			wantStatus: http.StatusNotFound,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			d, closeFn := mustCreateDB(t)
			defer closeFn()
			ctx := context.Background()
			// Set up witness.
			w := newWitness(t, d, []logOpts{{ID: test.setID,
				PK: test.setPK}})
			// Set an STH for the log if we want to for this test.
			if test.sth != nil {
				if _, err := w.Update(ctx, test.setID, test.sth, nil); err != nil {
					t.Errorf("failed to set STH: %v", err)
				}
			}
			// Now set up the http server.
			ts, tsCloseFn := createTestEnv(w)
			defer tsCloseFn()
			client := ts.Client()
			chkptQ := fmt.Sprintf(api.HTTPGetSTH, url.PathEscape(test.queryID))
			url := fmt.Sprintf("%s%s", ts.URL, chkptQ)
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("error response: %v", err)
			}
			if got, want := resp.StatusCode, test.wantStatus; got != want {
				t.Errorf("status code got %d, want %d", got, want)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	for _, test := range []struct {
		desc       string
		initC      []byte
		initSize   uint64
		body       api.UpdateRequest
		wantStatus int
	}{
		{
			desc:       "happy path",
			initC:      mInit,
			initSize:   5,
			body:       api.UpdateRequest{STH: mNext, Proof: consProof},
			wantStatus: http.StatusOK,
		}, {
			desc:       "smaller STH",
			initC:      mNext,
			initSize:   8,
			body:       api.UpdateRequest{STH: mInit, Proof: consProof},
			wantStatus: http.StatusConflict,
		}, {
			desc:     "garbage proof",
			initC:    mInit,
			initSize: 5,
			body: api.UpdateRequest{STH: mNext, Proof: [][]byte{
				dh("aaaa", 2),
				dh("bbbb", 2),
				dh("cccc", 2),
				dh("dddd", 2),
			}},
			wantStatus: http.StatusConflict,
		}, {
			desc:       "garbage STH",
			initC:      mInit,
			initSize:   5,
			body:       api.UpdateRequest{STH: []byte("aaa"), Proof: consProof},
			wantStatus: http.StatusInternalServerError,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			d, closeFn := mustCreateDB(t)
			defer closeFn()
			ctx := context.Background()
			logID := mID
			// Set up witness.
			w := newWitness(t, d, []logOpts{{ID: logID,
				PK: mPK}})
			// Set an initial STH for the log.
			if _, err := w.Update(ctx, logID, test.initC, nil); err != nil {
				t.Errorf("failed to set STH: %v", err)
			}
			// Now set up the http server.
			ts, tsCloseFn := createTestEnv(w)
			defer tsCloseFn()
			// Update to a newer STH.
			client := ts.Client()
			reqBody, err := json.Marshal(test.body)
			if err != nil {
				t.Fatalf("couldn't parse request: %v", err)
			}
			url := fmt.Sprintf("%s%s", ts.URL, fmt.Sprintf(api.HTTPUpdate, url.PathEscape(logID)))
			req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(string(reqBody)))
			if err != nil {
				t.Fatalf("couldn't form http request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("error response: %v", err)
			}
			if got, want := resp.StatusCode, test.wantStatus; got != want {
				t.Errorf("status code got %d, want %d", got, want)
			}
		})
	}
}
