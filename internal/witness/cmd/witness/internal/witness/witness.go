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

// Package witness is designed to make sure the STHs of CT logs are consistent
// and store/serve/sign them if so.  It is expected that a separate feeder
// component would be responsible for the actual interaction with logs.
package witness

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/internal/witness/api"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Opts is the options passed to a witness.
type Opts struct {
	DB        *sql.DB
	PrivKey   string
	KnownLogs map[string]ct.SignatureVerifier
}

// Witness consists of a database for storing STHs, a signing key, and a list
// of logs for which it stores and verifies STHs.
type Witness struct {
	db   *sql.DB
	sk   crypto.PrivateKey
	Logs map[string]ct.SignatureVerifier
}

// New creates a new witness, which initially has no logs to follow.
func New(wo Opts) (*Witness, error) {
	// Create the sths table if needed.
	_, err := wo.DB.Exec(`CREATE TABLE IF NOT EXISTS sths (logID BLOB PRIMARY KEY, sth BLOB)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %v", err)
	}
	// Parse the PEM-encoded secret key.
	p, _ := pem.Decode([]byte(wo.PrivKey))
	if p == nil {
		return nil, errors.New("no PEM block found in secret key string")
	}
	sk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	// x509 can return either the key object or a pointer to it.  This
	// discrepancy is handled in the same way as in tls/signature_test.go,
	// namely changing it to be the object if it's a pointer.
	if reflect.TypeOf(sk).Kind() == reflect.Ptr {
		sk = reflect.ValueOf(sk).Elem().Interface()
	}
	return &Witness{
		db:   wo.DB,
		sk:   sk,
		Logs: wo.KnownLogs,
	}, nil
}

// parse verifies the STH under the appropriate key for logID and returns
// the parsed STH.  If the STH contained an incorrect logID the witness returns
// an error indicating this, and if the logID is missing the witness fills it in.
// This assumes sthRaw parses as a SignedTreeHead (not a CosignedSTH), so STHs are
// stored unsigned and signed only right when they are being returned.
func (w *Witness) parse(sthRaw []byte, logID string) (*ct.SignedTreeHead, error) {
	sv, ok := w.Logs[logID]
	if !ok {
		return nil, fmt.Errorf("log %q not found", logID)
	}
	var sth ct.SignedTreeHead
	if err := json.Unmarshal(sthRaw, &sth); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %v", err)
	}
	var idHash ct.SHA256Hash
	if err := idHash.FromBase64String(logID); err != nil {
		return nil, fmt.Errorf("failed to decode logID: %v", err)
	}
	var empty ct.SHA256Hash
	if bytes.Equal(sth.LogID[:], empty[:]) {
		sth.LogID = idHash
	} else if !bytes.Equal(sth.LogID[:], idHash[:]) {
		return nil, status.Errorf(codes.FailedPrecondition, "STH logID = %q, input logID = %q", sth.LogID.Base64String(), logID)
	}
	if err := sv.VerifySTHSignature(sth); err != nil {
		return nil, fmt.Errorf("failed to verify STH signature: %v", err)
	}
	return &sth, nil
}

// GetLogs returns a list of all logs the witness is aware of.
func (w *Witness) GetLogs() ([]string, error) {
	rows, err := w.db.Query("SELECT logID FROM sths")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []string
	for rows.Next() {
		var logID string
		err := rows.Scan(&logID)
		if err != nil {
			return nil, err
		}
		logs = append(logs, logID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}

// GetSTH gets a cosigned STH for a given log, which is consistent with all
// other STHs for the same log signed by this witness.
func (w *Witness) GetSTH(logID string) ([]byte, error) {
	sthRaw, err := w.getLatestSTH(w.db.QueryRow, logID)
	if err != nil {
		return nil, err
	}
	sth, err := w.parse(sthRaw, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse raw STH: %v", err)
	}
	signed, err := w.signSTH(sth)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign retrieved STH: %v", err)
	}
	return signed, nil
}

// Update updates the latest STH if nextRaw is consistent with the current
// latest one for this log. It returns the latest cosigned STH held by
// the witness, which is a signed version of nextRaw if the update was applied.
func (w *Witness) Update(ctx context.Context, logID string, nextRaw []byte, pf [][]byte) ([]byte, error) {
	// If we don't witness this log then no point in going further.
	_, ok := w.Logs[logID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "log %q not found", logID)
	}
	// Check the signatures on the raw STH and parse it into the STH format.
	next, err := w.parse(nextRaw, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse input STH: %v", err)
	}
	// Get the latest one for the log because we don't want consistency proofs
	// with respect to older STHs.  Bind this all in a transaction to
	// avoid race conditions when updating the database.
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't create db tx: %v", err)
	}
	defer tx.Rollback()

	// Get the latest STH (if one exists).
	prevRaw, err := w.getLatestSTH(tx.QueryRow, logID)
	if err != nil {
		// If there was nothing stored already then treat this new
		// STH as trust-on-first-use (TOFU).
		if status.Code(err) == codes.NotFound {
			if err := w.setSTH(tx, logID, nextRaw); err != nil {
				return nil, fmt.Errorf("couldn't set TOFU STH: %v", err)
			}
			signed, err := w.signSTH(next)
			if err != nil {
				return nil, fmt.Errorf("couldn't sign STH: %v", err)
			}
			return signed, nil
		}
		return nil, fmt.Errorf("couldn't retrieve latest STH: %w", err)
	}
	// Parse the raw retrieved STH into the STH format.
	prev, err := w.parse(prevRaw, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse stored STH: %v", err)
	}
	if next.TreeSize < prev.TreeSize {
		// Complain if prev is bigger than next.
		return prevRaw, status.Errorf(codes.FailedPrecondition, "cannot prove consistency backwards (%d < %d)", next.TreeSize, prev.TreeSize)
	}
	if next.TreeSize == prev.TreeSize {
		if !bytes.Equal(next.SHA256RootHash[:], prev.SHA256RootHash[:]) {
			return prevRaw, status.Errorf(codes.FailedPrecondition, "STH for same size log with differing hash (got %x, have %x)", next.SHA256RootHash, prev.SHA256RootHash)
		}
		// If it's identical to the previous one do nothing.
		return prevRaw, nil
	}
	// The only remaining option is next.Size > prev.Size. This might be
	// valid so we verify the consistency proof.
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, prev.TreeSize, next.TreeSize, pf, prev.SHA256RootHash[:], next.SHA256RootHash[:]); err != nil {
		// Complain if the STHs aren't consistent.
		return prevRaw, status.Errorf(codes.FailedPrecondition, "failed to verify consistency proof: %v", err)
	}
	// If the consistency proof is good we store the raw STH and return the
	// signed one.
	if err := w.setSTH(tx, logID, nextRaw); err != nil {
		return nil, fmt.Errorf("failed to store new STH: %v", err)
	}
	signed, err := w.signSTH(next)
	if err != nil {
		return nil, fmt.Errorf("failed to sign new STH: %v", err)
	}
	return signed, nil
}

// signSTH adds the witness' signature to an STH.
func (w *Witness) signSTH(sth *ct.SignedTreeHead) ([]byte, error) {
	sigInput, err := tls.Marshal(*sth)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal signature input: %v", err)
	}
	sig, err := tls.CreateSignature(w.sk, tls.SHA256, sigInput)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign STH data: %v", err)
	}
	cosigned := api.CosignedSTH{SignedTreeHead: *sth,
		WitnessSigs: []ct.DigitallySigned{ct.DigitallySigned(sig)},
	}
	cosignedRaw, err := json.Marshal(cosigned)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal cosigned STH: %v", err)
	}
	return cosignedRaw, nil
}

// getLatestSTH returns the raw stored data for the latest STH of a given log.
func (w *Witness) getLatestSTH(queryRow func(query string, args ...interface{}) *sql.Row, logID string) ([]byte, error) {
	row := queryRow("SELECT sth FROM sths WHERE logID = ?", logID)
	if err := row.Err(); err != nil {
		return nil, err
	}
	var sth []byte
	if err := row.Scan(&sth); err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Errorf(codes.NotFound, "no STH for log %q", logID)
		}
		return nil, err
	}
	return sth, nil
}

// setSTH writes the STH to the database for a given log.
func (w *Witness) setSTH(tx *sql.Tx, logID string, sth []byte) error {
	if _, err := tx.Exec(`INSERT OR REPLACE INTO sths (logID, sth) VALUES (?, ?)`, logID, sth); err != nil {
		return fmt.Errorf("failed to update STH; %v", err)
	}
	return tx.Commit()
}
