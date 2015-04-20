// CT log client package contains types and code for interacting with
// RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/mreiferson/go-httpclient"
)

// URI paths for CT Log endpoints
const (
	AddChainPath    = "/ct/v1/add-chain"
	AddPreChainPath = "/ct/v1/add-pre-chain"
	GetSTHPath      = "/ct/v1/get-sth"
	GetEntriesPath  = "/ct/v1/get-entries"
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

// addChainRequest represents the JSON request body sent to the add-chain CT
// method.
type addChainRequest struct {
	Chain []string `json:"chain"`
}

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
	ExtraData string `json:"extra_data"`
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
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Keep-Alive", "timeout=15, max=100")
	resp, err := c.httpClient.Do(req)
	var body []byte
	if resp != nil {
		body, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(body, &res); err != nil {
		return err
	}
	return nil
}

// Makes a HTTP POST call to |uri|, and attempts to parse the response as a JSON
// representation of the structure in |res|.
// Returns a non-nil |error| if there was a problem.
func (c *LogClient) postAndParse(uri string, req interface{}, res interface{}) (*http.Response, string, error) {
	post_body, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	httpReq, err := http.NewRequest("POST", uri, bytes.NewReader(post_body))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Keep-Alive", "timeout=15, max=100")
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	// Read all of the body, if there is one, so that the http.Client can do
	// Keep-Alive:
	var body []byte
	if resp != nil {
		body, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		return resp, string(body), err
	}
	if resp.StatusCode == 200 {
		if err != nil {
			return resp, string(body), err
		}
		if err = json.Unmarshal(body, &res); err != nil {
			return resp, string(body), err
		}
	}
	return resp, "", nil
}

// Attempts to add |chain| to the log, using the api end-point specified by
// |path|.
func (c *LogClient) addChainWithRetry(path string, chain []ASN1Cert) (*SignedCertificateTimestamp, error) {
	var resp addChainResponse
	var req addChainRequest
	for _, link := range chain {
		req.Chain = append(req.Chain, base64.StdEncoding.EncodeToString(link))
	}
	done := false
	httpStatus := "Unknown"
	for !done {
		backoffSeconds := 0
		httpResp, errorBody, err := c.postAndParse(c.uri+path, &req, &resp)
		if err != nil {
			log.Printf("Got %s, backing off.", err)
			backoffSeconds = 10
		} else {
			switch {
			case httpResp.StatusCode == 200:
				done = true
				break
			case httpResp.StatusCode == 408:
			case httpResp.StatusCode == 503:
				// Retry
				backoffSeconds = 10
				if retryAfter := httpResp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, err := strconv.Atoi(retryAfter); err != nil {
						backoffSeconds = seconds
					}
				}
			default:
				return nil, fmt.Errorf("Got HTTP Status %s: %s", httpResp.Status, errorBody)
			}
			httpStatus = httpResp.Status
		}
		// Now back-off before retrying
		log.Printf("Got %s, backing-off %d seconds.", httpStatus, backoffSeconds)
		time.Sleep(time.Duration(backoffSeconds) * time.Second)
	}

	rawLogId, err := base64.StdEncoding.DecodeString(resp.ID)
	if err != nil {
		return nil, err
	}
	rawSignature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, err
	}
	return &SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      rawLogId,
		Timestamp:  resp.Timestamp,
		Extensions: CTExtensions(resp.Extensions),
		Signature:  rawSignature}, nil
}

// Adds the (DER represented) X509 |chain| to the log.
func (c *LogClient) AddChain(chain []ASN1Cert) (*SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(AddChainPath, chain)
}

// Add the (DER represented) Precertificate |chain| to the log.
func (c *LogClient) AddPreChain(chain []ASN1Cert) (*SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(AddPreChainPath, chain)
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
func (c *LogClient) GetEntries(start, end int64) ([]LogEntry, error) {
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
	entries := make([]LogEntry, end-start+1, end-start+1)
	for index, entry := range resp.Entries {
		leafBytes, err := base64.StdEncoding.DecodeString(entry.LeafInput)
		leaf, err := ReadMerkleTreeLeaf(bytes.NewBuffer(leafBytes))
		if err != nil {
			return nil, err
		}
		entries[index].Leaf = *leaf
		chainBytes, err := base64.StdEncoding.DecodeString(entry.ExtraData)

		var chain []ASN1Cert
		switch leaf.TimestampedEntry.EntryType {
		case X509LogEntryType:
			chain, err = UnmarshalX509ChainArray(chainBytes)

		case PrecertLogEntryType:
			chain, err = UnmarshalPrecertChainArray(chainBytes)

		default:
			return nil, fmt.Errorf("saw unknown entry type: %v", leaf.TimestampedEntry.EntryType)
		}
		if err != nil {
			return nil, err
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}
