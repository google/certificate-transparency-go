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

// Package http is a simple client for interacting with witnesses over HTTP.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	wit_api "github.com/google/certificate-transparency-go/internal/witness/api"
)

// ErrSTHTooOld is returned if the STH passed to Update needs to be updated.
var ErrSTHTooOld = errors.New("STH too old")

// Witness consists of the witness' URL and signature verifier.
type Witness struct {
	URL *url.URL
}

// GetLatestSTH returns a recent STH from the witness for the specified log ID.
func (w Witness) GetLatestSTH(ctx context.Context, logID string) ([]byte, error) {
	u, err := w.URL.Parse(fmt.Sprintf(wit_api.HTTPGetSTH, url.PathEscape(logID)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to do http request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, os.ErrNotExist
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status response: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// Update attempts to clock the witness forward for the given logID.
// The latest signed STH will be returned if this succeeds, or if the error is
// http.ErrSTHTooOld. In all other cases no STH should be expected.
func (w Witness) Update(ctx context.Context, logID string, sth []byte, proof [][]byte) ([]byte, error) {
	reqBody, err := json.MarshalIndent(&wit_api.UpdateRequest{
		STH:   sth,
		Proof: proof,
	}, "", " ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update request: %v", err)
	}
	u, err := w.URL.Parse(fmt.Sprintf(wit_api.HTTPUpdate, url.PathEscape(logID)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to do http request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 409 {
			return body, ErrSTHTooOld
		}
		return nil, fmt.Errorf("bad status response (%s): %q", resp.Status, body)
	}
	return body, nil
}
