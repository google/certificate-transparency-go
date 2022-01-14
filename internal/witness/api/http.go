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

// Package api provides the API endpoints for the witness.
package api

import (
	ct "github.com/google/certificate-transparency-go"
)

const (
	// HTTPGetSTH is the path of the URL to get an STH.  The
	// placeholder is for the logID (an alphanumeric string).
	HTTPGetSTH = "/ctwitness/v0/logs/%s/sth"
	// HTTPUpdate is the path of the URL to update to a new STH.
	// Again the placeholder is for the logID.
	HTTPUpdate = "/ctwitness/v0/logs/%s/update"
	// HTTPGetLogs is the path of the URL to get a list of all logs the
	// witness is aware of.
	HTTPGetLogs = "/ctwitness/v0/logs"
)

// UpdateRequest encodes the inputs to the witness Update function: a (raw)
// STH byte slice and a consistency proof (slice of slices).  The logID
// is part of the request URL.
type UpdateRequest struct {
	STH   []byte
	Proof [][]byte
}

// CosignedSTH has all the fields from a CT SignedTreeHead but adds a
// WitnessSigs field that holds the extra witness signatures.
type CosignedSTH struct {
	ct.SignedTreeHead
	WitnessSigs []ct.DigitallySigned `json:"witness_signatures"`
}
