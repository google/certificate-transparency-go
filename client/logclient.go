// CT log client package contains types and code for interacting with
// RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mreiferson/go-httpclient"
)

// URI paths for CT Log endpoints
const (
	GetSTHPath     = "/ct/v1/get-sth"
	GetEntriesPath = "/ct/v1/get-entries"
)

const (
	IssuerKeyHashLength = 32
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	uri        string       // the base URI of the log. e.g. http://ct.googleapis/pilot
	httpClient *http.Client // used to interact with the log via HTTP
}

//////////////////////////////////////////////////////////////////////////////////
// JSON structures follow.
// These represent the structures returned by the CT Log server.
//////////////////////////////////////////////////////////////////////////////////

// addChainResponse represents the JSON response to the add-chain CT method.
// An SCT represents a Log's promise to integrate a [pre-]certificate into the
// log within a defined period of time.
type addChainResponse struct {
	SCTVersion Version `json:"sct_version"` // SCT structure version
	ID         string  `json:"id"`          // Log ID
	Timestamp  uint64  `json:"timestamp"`   // Timestamp of issuance
	Extensions string  `json:"extensions"`  // Holder for any CT extensions
	Signature  string  `json:"signature"`   // Log signature for this SCT
}

// getSTHResponse respresents the JSON response to the get-sth CT method
type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    string `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature string `json:"tree_head_signature"` // Log signature for this STH
}

// base64LeafEntry respresents a Base64 encoded leaf entry
type base64LeafEntry struct {
	LeafInput string `json:"leaf_input"`
}

// getEntriesReponse respresents the JSON response to the CT get-entries method
type getEntriesResponse struct {
	Entries []base64LeafEntry `json:"entries"` // the list of returned entries
}

// getConsistencyProofResponse represents the JSON response to the CT get-consistency-proof method
type getConsistencyProofResponse struct {
	Consistency []string `json:"consistency"`
}

// getAuditProofResponse represents the JSON response to the CT get-audit-proof method
type getAuditProofResponse struct {
	Hash     []string `json:"hash"`      // the hashes which make up the proof
	TreeSize uint64   `json:"tree_size"` // the tree size against which this proof is constructed
}

// getAcceptedRootsResponse represents the JSON response to the CT get-roots method.
type getAcceptedRootsResponse struct {
	Certificates []string `json:"certificates"`
}

// getEntryAndProodReponse represents the JSON response to the CT get-entry-and-proof method
type getEntryAndProofResponse struct {
	LeafInput string   `json:"leaf_input"` // the entry itself
	ExtraData string   `json:"extra_data"` // any chain provided when the entry was added to the log
	AuditPath []string `json:"audit_path"` // the corresponding proof
}

// Constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// http://ct.googleapis.com/pilot
func New(uri string) *LogClient {
	var c LogClient
	c.uri = uri
	// TODO(alcutter): make these timeouts modifiable
	transport := &httpclient.Transport{
		ConnectTimeout:        10 * time.Second,
		RequestTimeout:        30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
	}
	c.httpClient = &http.Client{Transport: transport}
	return &c
}

// Makes a HTTP call to |uri|, and attempts to parse the response as a JSON
// representation of the structure in |res|.
// Returns a non-nil |error| if there was a problem.
func (c *LogClient) fetchAndParse(uri string, res interface{}) error {
	req, _ := http.NewRequest("GET", uri, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(body, &res); err != nil {
		return err
	}
	return nil
}

// Retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH() (sth *SignedTreeHead, err error) {
	var resp getSTHResponse
	if err = c.fetchAndParse(c.uri+GetSTHPath, &resp); err != nil {
		return
	}
	sth = &SignedTreeHead{
		TreeSize:  resp.TreeSize,
		Timestamp: resp.Timestamp,
	}
	if sth.SHA256RootHash, err = base64.StdEncoding.DecodeString(resp.SHA256RootHash); err != nil {
		return nil, errors.New("invalid base64 encoding in sha256_root_hash")
	}
	if len(sth.SHA256RootHash) != sha256.Size {
		return nil, errors.New("sha256_root_hash is invalid length")
	}
	if sth.TreeHeadSignature, err = base64.StdEncoding.DecodeString(resp.TreeHeadSignature); err != nil {
		return nil, errors.New("invalid base64 encoding in tree_head_signature")
	}
	// TODO(alcutter): Verify signature
	return
}

// Attempts to retrieve the entries in the sequence [|start|, |end|] from the CT
// log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(start, end int64) ([]LeafInput, error) {
	if end < 0 {
		return nil, errors.New("end should be >= 0")
	}
	if end < start {
		return nil, errors.New("start should be <= end")
	}
	var resp getEntriesResponse
	err := c.fetchAndParse(fmt.Sprintf("%s%s?start=%d&end=%d", c.uri, GetEntriesPath, start, end), &resp)
	if err != nil {
		return nil, err
	}
	entries := make([]LeafInput, end-start+1, end-start+1)
	for index, entry := range resp.Entries {
		entries[index], err = base64.StdEncoding.DecodeString(entry.LeafInput)
		if err != nil {
			return nil, err
		}
	}
	return entries, nil
}
