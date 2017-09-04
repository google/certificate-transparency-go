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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

// JSONClient provides common functionality for interacting with a JSON server
// that uses cryptographic signatures.
type JSONClient struct {
	uri        string                // the base URI of the server. e.g. http://ct.googleapis/pilot
	httpClient *http.Client          // used to interact with the server via HTTP
	Verifier   *ct.SignatureVerifier // nil for no verification (e.g. no public key available)
	logger     Logger                // interface to use for logging warnings and errors

	multiplier int64
	until      *time.Time
	mu         sync.RWMutex
}

var (
	baseBackoff = time.Second
	maxBackoff  = time.Second * 128
	jitter      = 250
)

func (c *JSONClient) setBackoff() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until != nil {
		return time.Until(*c.until)
	}
	c.multiplier++
	wait := baseBackoff * time.Duration(c.multiplier)
	if wait > maxBackoff {
		wait = maxBackoff
	}
	until := time.Now().Add(wait)
	c.until = &until
	go func() {
		time.Sleep(wait)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.until = nil
	}()
	return wait
}

func (c *JSONClient) decreaseBackoffMultiplier() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.multiplier > 0 {
		c.multiplier--
	}
	return
}

func (c *JSONClient) backoff(ctx context.Context) error {
	c.mu.RLock()
	if c.until == nil {
		c.mu.RUnlock()
		return nil
	}
	until := time.Until(*c.until)
	c.mu.RUnlock()
	// add jitter so everything doesn't fire off all at once
	until += time.Millisecond * time.Duration(rand.Intn(jitter))
	backoffTimer := time.NewTimer(until)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-backoffTimer.C:
	}
	return nil
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

// GetAndParse makes a HTTP GET call to the given path, and attempt to parse
// the response as a JSON representation of the rsp structure.  The provided
// context is used to control the HTTP call.
func (c *JSONClient) GetAndParse(ctx context.Context, path string, params map[string]string, rsp interface{}) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context.Context required")
	}
	// Build a GET request with URL-encoded parameters.
	vals := url.Values{}
	for k, v := range params {
		vals.Add(k, v)
	}
	fullURI := fmt.Sprintf("%s%s?%s", c.uri, path, vals.Encode())
	httpReq, err := http.NewRequest(http.MethodGet, fullURI, nil)
	if err != nil {
		return nil, err
	}

	httpRsp, err := ctxhttp.Do(ctx, c.httpClient, httpReq)
	if err != nil {
		return nil, err
	}
	// Make sure everything is read, so http.Client can reuse the connection.
	defer httpRsp.Body.Close()
	defer ioutil.ReadAll(httpRsp.Body)

	if httpRsp.StatusCode != http.StatusOK {
		return httpRsp, fmt.Errorf("got HTTP Status %q", httpRsp.Status)
	}

	if err := json.NewDecoder(httpRsp.Body).Decode(rsp); err != nil {
		return httpRsp, err
	}

	return httpRsp, nil
}

// PostAndParse makes a HTTP POST call to the given path, including the request
// parameters, and attempt to parse the response as a JSON representation of
// the rsp structure.  The provided context is used the control the HTTP call.
func (c *JSONClient) PostAndParse(ctx context.Context, path string, req, rsp interface{}) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context.Context required")
	}
	// Build a POST request with JSON body.
	postBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	fullURI := fmt.Sprintf("%s%s", c.uri, path)
	httpReq, err := http.NewRequest(http.MethodPost, fullURI, bytes.NewReader(postBody))
	if err != nil {
		return nil, err
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
		return httpRsp, err
	}
	if httpRsp.StatusCode == http.StatusOK {
		if err = json.Unmarshal(body, &rsp); err != nil {
			return httpRsp, err
		}
	}
	return httpRsp, nil
}

// PostAndParseWithRetry makes a HTTP POST call, but retries (with backoff) on
// retriable errors.
func (c *JSONClient) PostAndParseWithRetry(ctx context.Context, path string, req, rsp interface{}) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context.Context required")
	}
	for {
		if err := c.backoff(ctx); err != nil {
			return nil, err
		}
		httpRsp, err := c.PostAndParse(ctx, path, req, rsp)
		if err != nil {
			wait := c.setBackoff()
			c.logger.Printf("Request failed, backing-off for %s: %s", wait, err)
			continue
		}
		switch {
		case httpRsp.StatusCode == http.StatusOK:
			c.decreaseBackoffMultiplier()
			return httpRsp, nil
		case httpRsp.StatusCode == http.StatusRequestTimeout:
			// Request timeout, retry immediately
			c.logger.Printf("Request timed out, retrying immediately")
		case httpRsp.StatusCode == http.StatusServiceUnavailable:
			// Retry
			wait := c.setBackoff()
			c.logger.Printf("Request failed, backing-off for %s: got HTTP status %s", wait, httpRsp.Status)
		default:
			return nil, fmt.Errorf("got HTTP Status %q", httpRsp.Status)
		}
	}
}
