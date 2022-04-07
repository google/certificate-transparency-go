// Copyright 2016 Google LLC. All Rights Reserved.
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

// Package cmd implements subcommands of ctclient, the command-line utility for
// interacting with CT logs.
package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/spf13/cobra"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	logURI          string
	pubKey          string

	logMMD    time.Duration
	certChain string
	timestamp int64
	treeSize  uint64
	treeHash  string
	prevSize  uint64
	prevHash  string
	leafHash  string
)

func init() {
	flags := rootCmd.PersistentFlags()
	flags.BoolVar(&skipHTTPSVerify, "skip_https_verify", false, "Skip verification of HTTPS transport connection")
	flags.StringVar(&logName, "log_name", "", "Name of log to retrieve information from --log_list for")
	flags.StringVar(&logList, "log_list", loglist.AllLogListURL, "Location of master log list (URL or filename)")
	flags.StringVar(&logURI, "log_uri", "https://ct.googleapis.com/rocketeer", "CT log base URI")
	flags.StringVar(&pubKey, "pub_key", "", "Name of file containing log's public key")

	flags = rootCmd.LocalFlags()
	flags.DurationVar(&logMMD, "log_mmd", 24*time.Hour, "Log's maximum merge delay")
	flags.StringVar(&certChain, "cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
	flags.Int64Var(&timestamp, "timestamp", 0, "Timestamp to use for inclusion checking")
	flags.Uint64Var(&treeSize, "size", 0, "Tree size to query at")
	flags.StringVar(&treeHash, "tree_hash", "", "Tree hash to check against (as hex string or base64)")
	flags.Uint64Var(&prevSize, "prev_size", 0, "Previous tree size to get consistency against")
	flags.StringVar(&prevHash, "prev_hash", "", "Previous tree hash to check against (as hex string or base64)")
	flags.StringVar(&leafHash, "leaf_hash", "", "Leaf hash to retrieve (as hex string or base64)")
}

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "ctclient",
	Short: "A command line client for Certificate Transparency logs",

	Run: func(_ *cobra.Command, args []string) {
		runMain(args)
	},
}

// Execute adds all child commands to the root command and sets flags
// appropriately. It needs to be called exactly once by main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func signatureToString(signed *ct.DigitallySigned) string {
	return fmt.Sprintf("Signature: Hash=%v Sign=%v Value=%x", signed.Algorithm.Hash, signed.Algorithm.Signature, signed.Signature)
}

func exitWithDetails(err error) {
	if err, ok := err.(client.RspError); ok {
		glog.Infof("HTTP details: status=%d, body:\n%s", err.StatusCode, err.Body)
	}
	glog.Exit(err.Error())
}

func hashFromString(input string) ([]byte, error) {
	hash, err := hex.DecodeString(input)
	if err == nil && len(hash) == sha256.Size {
		return hash, nil
	}
	hash, err = base64.StdEncoding.DecodeString(input)
	if err == nil && len(hash) == sha256.Size {
		return hash, nil
	}
	return nil, fmt.Errorf("hash value %q failed to parse as 32-byte hex or base64", input)
}

func chainFromFile(filename string) ([]ct.ASN1Cert, int64) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		glog.Exitf("Failed to read certificate file: %v", err)
	}
	rest := contents
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	if len(chain) == 0 {
		glog.Exitf("No certificates found in %s", certChain)
	}

	// Also look for something like a text timestamp for convenience.
	var timestamp int64
	tsRE := regexp.MustCompile(`Timestamp[:=](\d+)`)
	for _, line := range strings.Split(string(contents), "\n") {
		x := tsRE.FindStringSubmatch(line)
		if len(x) > 1 {
			timestamp, err = strconv.ParseInt(x[1], 10, 64)
			if err != nil {
				break
			}
		}
	}
	return chain, timestamp
}

func addChain(ctx context.Context, logClient *client.LogClient) {
	if certChain == "" {
		glog.Exitf("No certificate chain file specified with -cert_chain")
	}
	chain, _ := chainFromFile(certChain)

	// Examine the leaf to see if it looks like a pre-certificate.
	isPrecert := false
	leaf, err := x509.ParseCertificate(chain[0].Data)
	if err == nil {
		count, _ := x509util.OIDInExtensions(x509.OIDExtensionCTPoison, leaf.Extensions)
		if count > 0 {
			isPrecert = true
			fmt.Print("Uploading pre-certificate to log\n")
		}
	}

	var sct *ct.SignedCertificateTimestamp
	if isPrecert {
		sct, err = logClient.AddPreChain(ctx, chain)
	} else {
		sct, err = logClient.AddChain(ctx, chain)
	}
	if err != nil {
		exitWithDetails(err)
	}
	// Calculate the leaf hash
	leafEntry := ct.CreateX509MerkleTreeLeaf(chain[0], sct.Timestamp)
	leafHash, err := ct.LeafHashForLeaf(leafEntry)
	if err != nil {
		glog.Exitf("Failed to create hash of leaf: %v", err)
	}

	// Display the SCT
	when := ct.TimestampToTime(sct.Timestamp)
	fmt.Printf("Uploaded chain of %d certs to %v log at %v, timestamp: %d (%v)\n", len(chain), sct.SCTVersion, logClient.BaseURI(), sct.Timestamp, when)
	fmt.Printf("LogID: %x\n", sct.LogID.KeyID[:])
	fmt.Printf("LeafHash: %x\n", leafHash)
	fmt.Printf("Signature: %v\n", signatureToString(&sct.Signature))

	age := time.Since(when)
	if age > logMMD {
		// SCT's timestamp is old enough that the certificate should be included.
		getInclusionProofForHash(ctx, logClient, leafHash[:])
	}
}

func findTimestamp(ctx context.Context, logClient *client.LogClient) {
	if timestamp == 0 {
		glog.Exit("No -timestamp option supplied")
	}
	target := timestamp
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		exitWithDetails(err)
	}
	getEntry := func(idx int64) *ct.RawLogEntry {
		entries, err := logClient.GetRawEntries(ctx, idx, idx)
		if err != nil {
			exitWithDetails(err)
		}
		if l := len(entries.Entries); l != 1 {
			glog.Exitf("Unexpected number (%d) of entries received requesting index %d", l, idx)
		}
		logEntry, err := ct.RawLogEntryFromLeaf(idx, &entries.Entries[0])
		if err != nil {
			glog.Exitf("Failed to parse leaf %d: %v", idx, err)
		}
		return logEntry
	}
	// Performing a binary search assumes that the timestamps are
	// monotonically increasing.
	idx := sort.Search(int(sth.TreeSize), func(idx int) bool {
		glog.V(1).Infof("check timestamp at index %d", idx)
		entry := getEntry(int64(idx))
		return entry.Leaf.TimestampedEntry.Timestamp >= uint64(target)
	})
	when := ct.TimestampToTime(uint64(target))
	if idx >= int(sth.TreeSize) {
		fmt.Printf("No entry with timestamp>=%d (%v) found up to tree size %d\n", target, when, sth.TreeSize)
		return
	}
	fmt.Printf("First entry with timestamp>=%d (%v) found at index %d\n", target, when, idx)
	showRawLogEntry(getEntry(int64(idx)))
}

func getInclusionProof(ctx context.Context, logClient client.CheckLogClient) {
	var hash []byte
	if len(leafHash) > 0 {
		var err error
		hash, err = hashFromString(leafHash)
		if err != nil {
			glog.Exitf("Invalid --leaf_hash supplied: %v", err)
		}
	} else if len(certChain) > 0 {
		// Build a leaf hash from the chain and a timestamp.
		chain, entryTimestamp := chainFromFile(certChain)
		if timestamp != 0 {
			entryTimestamp = timestamp // Use user-specified timestamp
		}
		if entryTimestamp == 0 {
			glog.Exit("No timestamp available to accompany certificate")
		}

		var leafEntry *ct.MerkleTreeLeaf
		cert, err := x509.ParseCertificate(chain[0].Data)
		if x509.IsFatal(err) {
			glog.Warningf("Failed to parse leaf certificate: %v", err)
			leafEntry = ct.CreateX509MerkleTreeLeaf(chain[0], uint64(entryTimestamp))
		} else if cert.IsPrecertificate() {
			leafEntry, err = ct.MerkleTreeLeafFromRawChain(chain, ct.PrecertLogEntryType, uint64(entryTimestamp))
			if err != nil {
				glog.Exitf("Failed to build pre-certificate leaf entry: %v", err)
			}
		} else {
			leafEntry = ct.CreateX509MerkleTreeLeaf(chain[0], uint64(entryTimestamp))
		}

		leafHash, err := ct.LeafHashForLeaf(leafEntry)
		if err != nil {
			glog.Exitf("Failed to create hash of leaf: %v", err)
		}
		hash = leafHash[:]

		// Print a warning if this timestamp is still within the MMD window
		when := ct.TimestampToTime(uint64(entryTimestamp))
		if age := time.Since(when); age < logMMD {
			glog.Warningf("WARNING: Timestamp (%v) is with MMD window (%v), log may not have incorporated this entry yet.", when, logMMD)
		}
	}
	if len(hash) != sha256.Size {
		glog.Exit("No leaf hash available")
	}
	getInclusionProofForHash(ctx, logClient, hash)
}

func getInclusionProofForHash(ctx context.Context, logClient client.CheckLogClient, hash []byte) {
	var sth *ct.SignedTreeHead
	size := treeSize
	if size <= 0 {
		var err error
		sth, err = logClient.GetSTH(ctx)
		if err != nil {
			exitWithDetails(err)
		}
		size = sth.TreeSize
	}
	// Display the inclusion proof.
	rsp, err := logClient.GetProofByHash(ctx, hash, size)
	if err != nil {
		exitWithDetails(err)
	}
	fmt.Printf("Inclusion proof for index %d in tree of size %d:\n", rsp.LeafIndex, size)
	for _, e := range rsp.AuditPath {
		fmt.Printf("  %x\n", e)
	}
	if sth != nil {
		// If we retrieved an STH we can verify the proof.
		verifier := merkle.NewLogVerifier(rfc6962.DefaultHasher)
		if err := verifier.VerifyInclusion(uint64(rsp.LeafIndex), sth.TreeSize, hash, rsp.AuditPath, sth.SHA256RootHash[:]); err != nil {
			glog.Exitf("Failed to VerifyInclusion(%d, %d)=%v", rsp.LeafIndex, sth.TreeSize, err)
		}
		fmt.Printf("Verified that hash %x + proof = root hash %x\n", hash, sth.SHA256RootHash)
	}
}

func getConsistencyProof(ctx context.Context, logClient client.CheckLogClient) {
	if treeSize <= 0 {
		glog.Exit("No valid --size supplied")
	}
	if prevSize <= 0 {
		glog.Exit("No valid --prev_size supplied")
	}
	var hash1, hash2 []byte
	if prevHash != "" {
		var err error
		hash1, err = hashFromString(prevHash)
		if err != nil {
			glog.Exitf("Invalid --prev_hash: %v", err)
		}
	}
	if treeHash != "" {
		var err error
		hash2, err = hashFromString(treeHash)
		if err != nil {
			glog.Exitf("Invalid --tree_hash: %v", err)
		}
	}
	if (hash1 != nil) != (hash2 != nil) {
		glog.Exitf("Need both --prev_hash and --tree_hash or neither")
	}
	getConsistencyProofBetween(ctx, logClient, prevSize, treeSize, hash1, hash2)
}

func getConsistencyProofBetween(ctx context.Context, logClient client.CheckLogClient, first, second uint64, prevHash, treeHash []byte) {
	proof, err := logClient.GetSTHConsistency(ctx, uint64(first), uint64(second))
	if err != nil {
		exitWithDetails(err)
	}
	fmt.Printf("Consistency proof from size %d to size %d:\n", first, second)
	for _, e := range proof {
		fmt.Printf("  %x\n", e)
	}
	if prevHash == nil || treeHash == nil {
		return
	}
	// We have tree hashes so we can verify the proof.
	verifier := merkle.NewLogVerifier(rfc6962.DefaultHasher)
	if err := verifier.VerifyConsistency(first, second, prevHash, treeHash, proof); err != nil {
		glog.Exitf("Failed to VerifyConsistency(%x @size=%d, %x @size=%d): %v", prevHash, first, treeHash, second, err)
	}
	fmt.Printf("Verified that hash %x @%d + proof = hash %x @%d\n", prevHash, first, treeHash, second)
}

func dieWithUsage(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "Usage: ctclient [options] <cmd>\n"+
		"where cmd is one of:\n"+
		"   sth           retrieve signed tree head\n"+
		"   upload        upload cert chain and show SCT (needs -cert_chain)\n"+
		"   getroots      show accepted roots\n"+
		"   getentries    get log entries (needs -first and -last)\n"+
		"   inclusion     get inclusion proof (needs -leaf_hash and optionally -size)\n"+
		"   consistency   get consistency proof (needs -size and -prev_size, optionally -tree_hash and -prev_hash)\n"+
		"   bisect        find log entry by timestamp (needs -timestamp)\n")
	os.Exit(1)
}

func connect(ctx context.Context) *client.LogClient {
	var tlsCfg *tls.Config
	if skipHTTPSVerify {
		glog.Warning("Skipping HTTPS connection verification")
		tlsCfg = &tls.Config{InsecureSkipVerify: skipHTTPSVerify}
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsCfg,
		},
	}
	opts := jsonclient.Options{UserAgent: "ct-go-ctclient/1.0"}
	if pubKey != "" {
		pubkey, err := ioutil.ReadFile(pubKey)
		if err != nil {
			glog.Exit(err)
		}
		opts.PublicKey = string(pubkey)
	}

	uri := logURI
	if logName != "" {
		llData, err := x509util.ReadFileOrURL(logList, httpClient)
		if err != nil {
			glog.Exitf("Failed to read log list: %v", err)
		}
		ll, err := loglist.NewFromJSON(llData)
		if err != nil {
			glog.Exitf("Failed to build log list: %v", err)
		}

		logs := ll.FindLogByName(logName)
		if len(logs) == 0 {
			glog.Exitf("No log with name like %q found in loglist %q", logName, logList)
		}
		if len(logs) > 1 {
			logNames := make([]string, len(logs))
			for i, log := range logs {
				logNames[i] = fmt.Sprintf("%q", log.Description)
			}
			glog.Exitf("Multiple logs with name like %q found in loglist: %s", logName, strings.Join(logNames, ","))
		}
		uri = "https://" + logs[0].URL
		if opts.PublicKey == "" {
			opts.PublicKeyDER = logs[0].Key
		}
	}

	glog.V(1).Infof("Use CT log at %s", uri)
	logClient, err := client.New(uri, httpClient, opts)
	if err != nil {
		glog.Exit(err)
	}

	return logClient
}

func runMain(args []string) {
	ctx := context.Background()
	logClient := connect(ctx)

	if len(args) != 1 {
		dieWithUsage("Need command argument")
	}
	cmd := args[0]
	switch cmd {
	case "upload":
		addChain(ctx, logClient)
	case "inclusion", "inclusion-proof":
		getInclusionProof(ctx, logClient)
	case "consistency":
		getConsistencyProof(ctx, logClient)
	case "bisect":
		findTimestamp(ctx, logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}
