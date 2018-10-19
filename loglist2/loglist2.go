// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package loglist2 allows parsing and searching of the master CT Log list.
// It expects the log list to conform to the v2beta schema.
package loglist2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/certificate-transparency-go/tls"
)

const (
	// LogListURL has the master URL for Google Chrome's log list.
	LogListURL = "https://www.gstatic.com/ct/log_list/v2beta/log_list.json"
	// LogListSignatureURL has the URL for the signature over Google Chrome's log list.
	LogListSignatureURL = "https://www.gstatic.com/ct/log_list/v2beta/log_list.sig"
	// AllLogListURL has the URL for the list of all known logs (which isn't signed).
	AllLogListURL = "https://www.gstatic.com/ct/log_list/v2beta/all_logs_list.json"
)

// Manually mapped from https://www.gstatic.com/ct/log_list/v2beta/log_list_schema.json

// LogList holds a collection of log operators.
type LogList struct {
	// Operators maps operator names to more information about them, e.g.
	// contact details and which logs they operate.
	Operators map[string]*Operator `json:"operators"`
}

// Operator describes an operator and their logs.
type Operator struct {
	Email []string        `json:"email,omitempty"`
	Logs  map[string]*Log `json:"logs"`
}

type Log struct {
	Description      []string          `json:"description,omitempty"`
	LogID            []byte            `json:"log_id"`
	Key              []byte            `json:"key"`
	URL              string            `json:"url"`
	DNS              string            `json:"dns,omitempty"` // DNS API endpoint for the log
	MMD              int32             `json:"mmd"`           // seconds
	State            *LogStates        `json:"state,omitempty"`
	TemporalInterval *TemporalInterval `json:"temporal_interval,omitempty"`
	Type             string            `json:"log_type,omitempty"`
}

type TemporalInterval struct {
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
}

type LogStates struct {
	Pending   *LogState       `json:"pending,omitempty"`
	Qualified *LogState       `json:"qualified,omitempty"`
	Usable    *LogState       `json:"usable,omitempty"`
	Frozen    *FrozenLogState `json:"frozen,omitempty"`
	Retired   *LogState       `json:"retired,omitempty"`
	Rejected  *LogState       `json:"rejected,omitempty"`
}

type LogState struct {
	Timestamp time.Time `json:"timestamp"`
}

type FrozenLogState struct {
	LogState
	FinalTreeHead TreeHead `json:"final_tree_head"`
}

type TreeHead struct {
	SHA256RootHash []byte `json:"sha256_root_hash"`
	TreeSize       int64  `json:"tree_size"`
}

// NewFromJSON creates a LogList from JSON encoded data.
func NewFromJSON(llData []byte) (*LogList, error) {
	var ll LogList
	if err := json.Unmarshal(llData, &ll); err != nil {
		return nil, fmt.Errorf("failed to parse log list: %v", err)
	}
	return &ll, nil
}

// NewFromSignedJSON creates a LogList from JSON encoded data, checking a
// signature along the way. The signature data should be provided as the
// raw signature data.
func NewFromSignedJSON(llData, rawSig []byte, pubKey crypto.PublicKey) (*LogList, error) {
	sigAlgo := tls.Anonymous
	switch pkType := pubKey.(type) {
	case *rsa.PublicKey:
		sigAlgo = tls.RSA
	case *ecdsa.PublicKey:
		sigAlgo = tls.ECDSA
	default:
		return nil, fmt.Errorf("Unsupported public key type %v", pkType)
	}
	tlsSig := tls.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: sigAlgo,
		},
		Signature: rawSig,
	}
	if err := tls.VerifySignature(pubKey, llData, tlsSig); err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}
	return NewFromJSON(llData)
}

// FindLogByName returns all logs whose names contain the given string.
func (ll *LogList) FindLogByName(name string) []*Log {
	name = strings.ToLower(name)
	var results []*Log
	for _, op := range ll.Operators {
		for logName, log := range op.Logs {
			if strings.Contains(strings.ToLower(logName), name) {
				results = append(results, log)
			}
		}
	}
	return results
}

// FindLogByURL finds the log with the given URL.
func (ll *LogList) FindLogByURL(url string) *Log {
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			// Don't count trailing slashes
			if strings.TrimRight(log.URL, "/") == strings.TrimRight(url, "/") {
				return log
			}
		}
	}
	return nil
}

// FindLogByKeyHash finds the log with the given key hash.
func (ll *LogList) FindLogByKeyHash(keyhash [sha256.Size]byte) *Log {
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			h := sha256.Sum256(log.Key)
			if bytes.Equal(h[:], keyhash[:]) {
				return log
			}
		}
	}
	return nil
}

// FindLogByKeyHashPrefix finds all logs whose key hash starts with the prefix.
func (ll *LogList) FindLogByKeyHashPrefix(prefix string) []*Log {
	var results []*Log
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			h := sha256.Sum256(log.Key)
			hh := hex.EncodeToString(h[:])
			if strings.HasPrefix(hh, prefix) {
				results = append(results, log)
			}
		}
	}
	return results
}

// FindLogByKey finds the log with the given DER-encoded key.
func (ll *LogList) FindLogByKey(key []byte) *Log {
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			if bytes.Equal(log.Key[:], key) {
				return log
			}
		}
	}
	return nil
}

var hexDigits = regexp.MustCompile("^[0-9a-fA-F]+$")

// FuzzyFindLog tries to find logs that match the given unspecified input,
// whose format is unspecified.  This generally returns a single log, but
// if text input that matches multiple log descriptions is provided, then
// multiple logs may be returned.
func (ll *LogList) FuzzyFindLog(input string) []*Log {
	input = strings.Trim(input, " \t")
	if logs := ll.FindLogByName(input); len(logs) > 0 {
		return logs
	}
	if log := ll.FindLogByURL(input); log != nil {
		return []*Log{log}
	}
	// Try assuming the input is binary data of some form.  First base64:
	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		if len(data) == sha256.Size {
			var hash [sha256.Size]byte
			copy(hash[:], data)
			if log := ll.FindLogByKeyHash(hash); log != nil {
				return []*Log{log}
			}
		}
		if log := ll.FindLogByKey(data); log != nil {
			return []*Log{log}
		}
	}
	// Now hex, but strip all internal whitespace first.
	input = stripInternalSpace(input)
	if data, err := hex.DecodeString(input); err == nil {
		if len(data) == sha256.Size {
			var hash [sha256.Size]byte
			copy(hash[:], data)
			if log := ll.FindLogByKeyHash(hash); log != nil {
				return []*Log{log}
			}
		}
		if log := ll.FindLogByKey(data); log != nil {
			return []*Log{log}
		}
	}
	// Finally, allow hex strings with an odd number of digits.
	if hexDigits.MatchString(input) {
		if logs := ll.FindLogByKeyHashPrefix(input); len(logs) > 0 {
			return logs
		}
	}

	return nil
}

func stripInternalSpace(input string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsSpace(r) {
			return r
		}
		return -1
	}, input)
}
