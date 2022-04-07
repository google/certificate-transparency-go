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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
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
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	logURI          string
	pubKey          string

	logMMD time.Duration
)

func init() {
	flags := rootCmd.PersistentFlags()
	flags.BoolVar(&skipHTTPSVerify, "skip_https_verify", false, "Skip verification of HTTPS transport connection")
	flags.StringVar(&logName, "log_name", "", "Name of log to retrieve information from --log_list for")
	flags.StringVar(&logList, "log_list", loglist.AllLogListURL, "Location of master log list (URL or filename)")
	flags.StringVar(&logURI, "log_uri", "https://ct.googleapis.com/rocketeer", "CT log base URI")
	flags.StringVar(&pubKey, "pub_key", "", "Name of file containing log's public key")

	rootCmd.LocalFlags().DurationVar(&logMMD, "log_mmd", 24*time.Hour, "Log's maximum merge delay")
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
	case "bisect":
		findTimestamp(ctx, logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}
