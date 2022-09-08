// Copyright 2022 Google LLC. All Rights Reserved.
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
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

const connectionFlags = "{--log_uri uri | --log_name name [--log_list {file|uri}]} [--pub_key file]"

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	logURI          string
	pubKey          string
)

func init() {
	// Add flags added with "flag" package, including klog, to Cobra flag set.
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	flags := rootCmd.PersistentFlags()
	flags.BoolVar(&skipHTTPSVerify, "skip_https_verify", false, "Skip verification of HTTPS transport connection")
	flags.StringVar(&logName, "log_name", "", "Name of log to retrieve information from --log_list for")
	flags.StringVar(&logList, "log_list", loglist3.AllLogListURL, "Location of master log list (URL or filename)")
	flags.StringVar(&logURI, "log_uri", "https://ct.googleapis.com/rocketeer", "CT log base URI")
	flags.StringVar(&pubKey, "pub_key", "", "Name of file containing log's public key")
}

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "ctclient",
	Short: "A command line client for Certificate Transparency logs",

	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		flag.Parse()
	},
}

// Execute adds all child commands to the root command and sets flags
// appropriately. It needs to be called exactly once by main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}

func signatureToString(signed *ct.DigitallySigned) string {
	return fmt.Sprintf("Signature: Hash=%v Sign=%v Value=%x", signed.Algorithm.Hash, signed.Algorithm.Signature, signed.Signature)
}

func exitWithDetails(err error) {
	if err, ok := err.(client.RspError); ok {
		klog.Infof("HTTP details: status=%d, body:\n%s", err.StatusCode, err.Body)
	}
	klog.Exit(err.Error())
}

func connect(ctx context.Context) *client.LogClient {
	var tlsCfg *tls.Config
	if skipHTTPSVerify {
		klog.Warning("Skipping HTTPS connection verification")
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
		pubkey, err := os.ReadFile(pubKey)
		if err != nil {
			klog.Exit(err)
		}
		opts.PublicKey = string(pubkey)
	}

	uri := logURI
	if logName != "" {
		llData, err := x509util.ReadFileOrURL(logList, httpClient)
		if err != nil {
			klog.Exitf("Failed to read log list: %v", err)
		}
		ll, err := loglist3.NewFromJSON(llData)
		if err != nil {
			klog.Exitf("Failed to build log list: %v", err)
		}

		logs := ll.FindLogByName(logName)
		if len(logs) == 0 {
			klog.Exitf("No log with name like %q found in loglist %q", logName, logList)
		}
		if len(logs) > 1 {
			logNames := make([]string, len(logs))
			for i, log := range logs {
				logNames[i] = fmt.Sprintf("%q", log.Description)
			}
			klog.Exitf("Multiple logs with name like %q found in loglist: %s", logName, strings.Join(logNames, ","))
		}
		uri = "https://" + logs[0].URL
		if opts.PublicKey == "" {
			opts.PublicKeyDER = logs[0].Key
		}
	}

	klog.V(1).Infof("Use CT log at %s", uri)
	logClient, err := client.New(uri, httpClient, opts)
	if err != nil {
		klog.Exit(err)
	}

	return logClient
}
