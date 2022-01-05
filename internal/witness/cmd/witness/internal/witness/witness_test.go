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

package witness

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/internal/witness/api"
	"github.com/google/certificate-transparency-go/tls"
	_ "github.com/mattn/go-sqlite3" // Load drivers for sqlite3
)

var (
	// https://play.golang.org/p/gCY2Zi2BJ8G to generate keys and
	// https://play.golang.org/p/KUXRShKdYTb to sign things with loaded
	// keys.  Importantly, need to switch to using MarshalPKCS8PrivateKey
	// for the witness keys.
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

func mustCreatePK(pkPem string) crypto.PublicKey {
	pk, _, _, err := ct.PublicKeyFromPEM([]byte(pkPem))
	if err != nil {
		panic(err)
	}
	return pk
}

func newWitness(t *testing.T, d *sql.DB, logs []logOpts) *Witness {
	// Set up Opts for the witness.
	logMap := make(map[string]ct.SignatureVerifier)
	for _, log := range logs {
		sigV, err := ct.NewSignatureVerifier(log.PK)
		if err != nil {
			t.Fatalf("couldn't create a log verifier: %v", err)
		}
		logMap[log.ID] = *sigV
	}
	opts := Opts{
		DB:        d,
		PrivKey:   wSK,
		KnownLogs: logMap,
	}
	// Create the witness.
	w, err := New(opts)
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

func TestGetLogs(t *testing.T) {
	for _, test := range []struct {
		desc   string
		logIDs []string
		logPKs []crypto.PublicKey
		sths   [][]byte
	}{
		{
			desc:   "no logs",
			logIDs: []string{},
		}, {
			desc:   "one log",
			logIDs: []string{mID},
			logPKs: []crypto.PublicKey{mPK},
			sths:   [][]byte{mInit},
		}, {
			desc:   "two logs",
			logIDs: []string{bID, mID},
			logPKs: []crypto.PublicKey{bPK, mPK},
			sths:   [][]byte{bInit, mInit},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			d, closeFn := mustCreateDB(t)
			defer closeFn()
			ctx := context.Background()
			// Set up witness.
			logs := make([]logOpts, len(test.logIDs))
			for i, logID := range test.logIDs {
				logs[i] = logOpts{ID: logID,
					PK: test.logPKs[i],
				}
			}
			w := newWitness(t, d, logs)
			// Update to an STH for all logs.
			for i, logID := range test.logIDs {
				if _, err := w.Update(ctx, logID, test.sths[i], nil); err != nil {
					t.Errorf("failed to set STH: %v", err)
				}
			}
			// Now see if the witness knows about these logs.
			knownLogs, err := w.GetLogs()
			if err != nil {
				t.Fatalf("couldn't get logs from witness: %v", err)
			}
			if len(knownLogs) != len(test.logIDs) {
				t.Fatalf("got %d logs, want %d", len(knownLogs), len(test.logIDs))
			}
			sort.Strings(knownLogs)
			for i := range knownLogs {
				if knownLogs[i] != test.logIDs[i] {
					t.Fatalf("got %q, want %q", test.logIDs[i], knownLogs[i])
				}
			}
		})
	}
}

func TestGetSTH(t *testing.T) {
	for _, test := range []struct {
		desc      string
		setID     string
		setPK     crypto.PublicKey
		queryID   string
		queryPK   crypto.PublicKey
		sth       []byte
		wantThere bool
	}{
		{
			desc:      "happy path",
			setID:     mID,
			setPK:     mPK,
			queryID:   mID,
			queryPK:   mPK,
			sth:       mInit,
			wantThere: true,
		}, {
			desc:      "other log",
			setID:     mID,
			setPK:     mPK,
			queryID:   bID,
			queryPK:   bPK,
			sth:       mInit,
			wantThere: false,
		}, {
			desc:      "nothing there",
			setID:     mID,
			setPK:     mPK,
			queryID:   mID,
			queryPK:   mPK,
			sth:       nil,
			wantThere: false,
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
			// Try to get the latest STH.
			sthRaw, err := w.GetSTH(test.queryID)
			if !test.wantThere && err == nil {
				t.Fatalf("returned an STH but shouldn't have")
			}
			// Check to see if we got something.
			if test.wantThere {
				if err != nil {
					t.Fatalf("failed to get latest: %v", err)
				}
				sv, err := ct.NewSignatureVerifier(wPK)
				if err != nil {
					t.Fatalf("failed to create signature verifier: %v", err)
				}
				var sth api.CosignedSTH
				if err := json.Unmarshal(sthRaw, &sth); err != nil {
					t.Fatalf("failed to unmarshal raw STH: %v", err)
				}
				sig := tls.DigitallySigned(sth.WitnessSigs[0])
				sigData, err := tls.Marshal(sth.SignedTreeHead)
				if err != nil {
					t.Fatalf("failed to marshal internal STH: %v", err)
				}
				if err := sv.VerifySignature(sigData, sig); err != nil {
					t.Fatal("failed to verify co-signature")
				}
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	for _, test := range []struct {
		desc     string
		initSTH  []byte
		initSize uint64
		newSTH   []byte
		pf       [][]byte
		isGood   bool
	}{
		{
			desc:     "happy path",
			initSTH:  mInit,
			initSize: 5,
			newSTH:   mNext,
			pf:       consProof,
			isGood:   true,
		}, {
			desc:     "smaller STH",
			initSTH:  mNext,
			initSize: 8,
			newSTH:   mInit,
			pf:       consProof,
			isGood:   false,
		}, {
			desc:     "garbage proof",
			initSTH:  mInit,
			initSize: 5,
			newSTH:   mNext,
			pf: [][]byte{
				dh("aaaa", 2),
				dh("bbbb", 2),
				dh("cccc", 2),
				dh("dddd", 2),
			},
			isGood: false,
		}, {
			desc:     "right logID",
			initSTH:  mInit,
			initSize: 5,
			newSTH:   []byte(`{"log_id":"fRThG/6Ymon8NnpRMQJIgCMgjtrBVnOidYenOB0n6FI=","tree_size":8,"timestamp":1,"sha256_root_hash":"V8K9aklZ4EPB+RMOk1/8VsJUdFZR77GDtZUQq84vSbo=","tree_head_signature":"BAMARzBFAiEA2yPvkeRF0cvGOAxx0s+NUf7LT9gumx3MDYob3swzgHgCICGN1tbbu8FqagkE5kV0DSL3CsQWjv095AeL7b+iFMOu"}`),
			pf:       consProof,
			isGood:   true,
		}, {
			desc:     "wrong logID",
			initSTH:  mInit,
			initSize: 5,
			newSTH:   []byte(`{"log_id":"aaaaa/6Ymon8NnpRMQJIgCMgjtrBVnOidYenOB0n6FI=","tree_size":8,"timestamp":1,"sha256_root_hash":"V8K9aklZ4EPB+RMOk1/8VsJUdFZR77GDtZUQq84vSbo=","tree_head_signature":"BAMARzBFAiEA2yPvkeRF0cvGOAxx0s+NUf7LT9gumx3MDYob3swzgHgCICGN1tbbu8FqagkE5kV0DSL3CsQWjv095AeL7b+iFMOu"}`),
			pf:       consProof,
			isGood:   false,
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
			if _, err := w.Update(ctx, logID, test.initSTH, nil); err != nil {
				t.Errorf("failed to set STH: %v", err)
			}
			// Now update from this STH to a newer one.
			_, err := w.Update(ctx, logID, test.newSTH, test.pf)
			if test.isGood {
				if err != nil {
					t.Fatalf("can't update to new STH: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("should have gotten an error but didn't")
				}
			}
		})
	}
}
