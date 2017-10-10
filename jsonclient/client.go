// Copyright 2016 Google Inc. All Rights Reserved.
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

package jsonclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/net/context/ctxhttp"
)

// JSONClient provides common functionality for interacting with a JSON server
// that uses cryptographic signatures.
type JSONClient struct {
	uri        string                // the base URI of the server. e.g. http://ct.googleapis/pilot
	httpClient *http.Client          // used to interact with the server via HTTP
	Verifier   *ct.SignatureVerifier // nil for no verification (e.g. no public key available)
	logger     Logger                // interface to use for logging warnings and errors
}

// Logger is a simple logging interface used to log internal errors and warnings
type Logger interface {
	// Printf formats and logs a message
	Printf(string, ...interface{})
}

// Options are the options for creating a new JSONClient.
type Options struct {
	// Interface to use for logging warnings and errors, if nil the
	// standard library log package will be used.
	Logger Logger
	// PEM format public key to use for signature verification.
	PublicKey string
	// DER format public key to use for signature verification.
	PublicKeyDER []byte
}

// ParsePublicKey parses and returns the public key contained in opts.
// If both opts.PublicKey and opts.PublicKeyDER are set, PublicKeyDER is used.
// If neither is set, nil will be returned.
func (opts *Options) ParsePublicKey() (crypto.PublicKey, error) {
	if len(opts.PublicKeyDER) > 0 {
		return x509.ParsePKIXPublicKey(opts.PublicKeyDER)
	}

	if opts.PublicKey != "" {
		pubkey, _ /* keyhash */, rest, err := ct.PublicKeyFromPEM([]byte(opts.PublicKey))
		if err != nil {
			return nil, err
		}
		if len(rest) > 0 {
			return nil, errors.New("extra data found after PEM key decoded")
		}
		return pubkey, nil
	}

	return nil, nil
}

type basicLogger struct{}

func (bl *basicLogger) Printf(msg string, args ...interface{}) {
	log.Printf(msg, args...)
}

// New constructs a new JSONClient instance, for the given base URI, using the
// given http.Client object (if provided) and the Options object.
// If opts does not specify a public key, signatures will not be verified.
func New(uri string, hc *http.Client, opts Options) (*JSONClient, error) {
	pubkey, err := opts.ParsePublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	var verifier *ct.SignatureVerifier
	if pubkey != nil {
		var err error
		verifier, err = ct.NewSignatureVerifier(pubkey)
		if err != nil {
			return nil, err
		}
	}

	if hc == nil {
		hc = new(http.Client)
	}
	logger := opts.Logger
	if logger == nil {
		logger = &basicLogger{}
	}
	return &JSONClient{
		uri:        strings.TrimRight(uri, "/"),
		httpClient: hc,
		Verifier:   verifier,
		logger:     logger,
	}, nil
}

// GetAndParse makes a HTTP GET call to the given path, and attempta to parse
// the response as a JSON representation of the rsp structure.  Returns the
// http.Response, the body of the response, and an error.  Note that the
// returned http.Response can be non-nil even when an error is returned,
// in particular when the HTTP status is not OK or when the JSON parsing fails.
func (c *JSONClient) GetAndParse(ctx context.Context, path string, params map[string]string, rsp interface{}) (*http.Response, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("context.Context required")
	}
	// Build a GET request with URL-encoded parameters.
	vals := url.Values{}
	for k, v := range params {
		vals.Add(k, v)
	}
	fullURI := fmt.Sprintf("%s%s?%s", c.uri, path, vals.Encode())
	httpReq, err := http.NewRequest(http.MethodGet, fullURI, nil)
	if err != nil {
		return nil, nil, err
	}

	httpRsp, err := ctxhttp.Do(ctx, c.httpClient, httpReq)
	if err != nil {
		return nil, nil, err
	}

	// Read everything now so http.Client can reuse the connection.
	body, err := ioutil.ReadAll(httpRsp.Body)
	httpRsp.Body.Close()
	if err != nil {
		return httpRsp, body, fmt.Errorf("failed to read response body: %v", err)
	}

	if httpRsp.StatusCode != http.StatusOK {
		return httpRsp, body, fmt.Errorf("got HTTP Status %q", httpRsp.Status)
	}

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(rsp); err != nil {
		return httpRsp, body, err
	}

	return httpRsp, body, nil
}

// PostAndParse makes a HTTP POST call to the given path, including the request
// parameters, and attempts to parse the response as a JSON representation of
// the rsp structure. Returns the http.Response, the body of the response, and
// an error.  Note that the returned http.Response can be non-nil even when an
// error is returned, in particular when the HTTP status is not OK or when the
// JSON parsing fails.
func (c *JSONClient) PostAndParse(ctx context.Context, path string, req, rsp interface{}) (*http.Response, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("context.Context required")
	}
	// Build a POST request with JSON body.
	postBody, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	fullURI := fmt.Sprintf("%s%s", c.uri, path)
	httpReq, err := http.NewRequest(http.MethodPost, fullURI, bytes.NewReader(postBody))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpRsp, err := ctxhttp.Do(ctx, c.httpClient, httpReq)

	// Read all of the body, if there is one, so that the http.Client can do Keep-Alive.
	var body []byte
	if httpRsp != nil {
		body, err = ioutil.ReadAll(httpRsp.Body)
		httpRsp.Body.Close()
	}
	if err != nil {
		return httpRsp, body, err
	}

	if httpRsp.StatusCode == http.StatusOK {
		if err = json.Unmarshal(body, &rsp); err != nil {
			return httpRsp, body, err
		}
	}
	return httpRsp, body, nil
}

var maxBackoffInterval = 128 * time.Second

func calculateBackoff(interval time.Duration) (time.Duration, time.Duration) {
	backoff := interval
	interval *= 2
	if interval > maxBackoffInterval {
		interval = maxBackoffInterval
	}
	return backoff, interval
}

// PostAndParseWithRetry makes a HTTP POST call, but retries (with backoff) on
// retriable errors; the caller should set a deadline on the provided context
// to prevent infinite retries.  Return values are as for PostAndParse.
func (c *JSONClient) PostAndParseWithRetry(ctx context.Context, path string, req, rsp interface{}) (*http.Response, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("context.Context required")
	}
	// Retry after 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 128s, ....
	backoffInterval := 1 * time.Second
	backoffSeconds := time.Duration(0)
	for {
		err := backoffForRetry(ctx, backoffSeconds)
		if err != nil {
			return nil, nil, err
		}
		if backoffSeconds > 0 {
			backoffSeconds = time.Duration(0)
		}
		httpRsp, body, err := c.PostAndParse(ctx, path, req, rsp)
		if err != nil {
			backoffSeconds, backoffInterval = calculateBackoff(backoffInterval)
			c.logger.Printf("Request failed, backing-off for %s: %s", backoffSeconds, err)
			continue
		}
		switch {
		case httpRsp.StatusCode == http.StatusOK:
			return httpRsp, body, nil
		case httpRsp.StatusCode == http.StatusRequestTimeout:
			// Request timeout, retry immediately
			c.logger.Printf("Request timed out, retrying immediately")
		case httpRsp.StatusCode == http.StatusServiceUnavailable:
			// Retry
			backoffSeconds, backoffInterval = calculateBackoff(backoffInterval)
			// Retry-After may be either a number of seconds as a int or a RFC 1123
			// date string (RFC 7231 Section 7.1.3)
			if retryAfter := httpRsp.Header.Get("Retry-After"); retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					backoffSeconds = time.Duration(seconds) * time.Second
				} else if date, err := time.Parse(time.RFC1123, retryAfter); err == nil {
					backoffSeconds = date.Sub(time.Now())
				}
			}
			c.logger.Printf("Request failed, backing-off for %s: got HTTP status %s", backoffSeconds, httpRsp.Status)
		default:
			return nil, body, fmt.Errorf("got HTTP Status %q", httpRsp.Status)
		}
	}
}

func backoffForRetry(ctx context.Context, d time.Duration) error {
	backoffTimer := time.NewTimer(d)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-backoffTimer.C:
	}
	return nil
}
