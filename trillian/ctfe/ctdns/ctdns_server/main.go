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

// The ctdns_server binary runs the CT personality for DNS.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/etcd/clientv3"
	etcdnaming "github.com/coreos/etcd/clientv3/naming"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/ctfe/ctdns"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/naming"

	// Register PEMKeyFile, PrivateKey and PKCS11Config ProtoHandlers
	_ "github.com/google/trillian/crypto/keys/der/proto"
	_ "github.com/google/trillian/crypto/keys/pem/proto"
	_ "github.com/google/trillian/crypto/keys/pkcs11/proto"
)

// Global flags that affect all log instances.
var (
	metricsEndpoint    = flag.String("metrics_endpoint", "localhost:8053", "Endpoint for serving metrics; if left empty, metrics will be visible on --http_endpoint")
	baseURI            = flag.String("base_uri", "", "The CTFE URI under which all the logs are served")
	httpTimeout        = flag.Duration("http_timeout", time.Second*10, "Deadline for backend HTTP requests")
	logConfig          = flag.String("log_config", "", "File holding log config in text proto format")
	multiBackendConfig = flag.Bool("multi_backend_config", false, "If true the logConfig file is in multi backend format")
	etcdServers        = flag.String("etcd_servers", "", "A comma-separated list of etcd servers")
	etcdMetricsService = flag.String("etcd_metrics_service", "trillian-ctdns-metrics-http", "Service name to announce our HTTP metrics endpoint under")
	startupWait        = flag.Duration("startup_wait", time.Second*5, "How long to wait for UDP server startup")
)

func main() {
	// TODO(Martin2112): Share some of the code in this file with CTFE not copy.
	flag.Parse()
	ctx := context.Background()

	if len(*baseURI) == 0 {
		glog.Exitf("The --base_uri of the CTFE server must be specified.")
	}

	var cfg *configpb.LogMultiConfig
	var err error
	// Get log config from file before we start. This is a different proto
	// type if we're using a multi backend configuration.
	if *multiBackendConfig {
		cfg, err = readMultiCfg(*logConfig)
	} else {
		cfg, err = readCfg(*logConfig, "")
	}

	if err != nil {
		glog.Exitf("Failed to read config: %v", err)
	}

	if _, err := ctfe.ValidateLogMultiConfig(cfg); err != nil {
		glog.Exitf("Invalid config: %v", err)
	}

	glog.CopyStandardLogTo("WARNING")
	glog.Info("**** CT DNS Server Starting ****")

	if len(*etcdServers) > 0 {
		// Use etcd to provide endpoint resolution.
		cfg := clientv3.Config{Endpoints: strings.Split(*etcdServers, ","), DialTimeout: 5 * time.Second}
		client, err := clientv3.New(cfg)
		if err != nil {
			glog.Exitf("Failed to connect to etcd at %v: %v", *etcdServers, err)
		}
		etcdRes := &etcdnaming.GRPCResolver{Client: client}

		// Also announce ourselves.
		updateMetrics := naming.Update{Op: naming.Add, Addr: *metricsEndpoint}
		glog.Infof("Announcing our presence in %v with %+v", *etcdMetricsService, updateMetrics)
		etcdRes.Update(ctx, *etcdMetricsService, updateMetrics)

		byeMetrics := naming.Update{Op: naming.Delete, Addr: *metricsEndpoint}
		defer func() {
			glog.Infof("Removing our presence in %v with %+v", *etcdMetricsService, byeMetrics)
			etcdRes.Update(ctx, *etcdMetricsService, byeMetrics)
		}()
	}

	httpClient := &http.Client{
		Timeout: *httpTimeout,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// Register DNS handlers for all the configured logs using the correct RPC
	// client. Ignore any that don't specify a zone.
	var zones int
	for _, c := range cfg.LogConfigs.Config {
		if len(c.DnsZone) > 0 {
			zones++
			if err := setupDNSHandler(httpClient, *baseURI, c); err != nil {
				glog.Exitf("Failed to set up DNS log instance for %+v: %v", cfg, err)
			}
		}
	}

	if zones == 0 {
		glog.Exitf("No logs have a dns_zone configured. Exiting.")
	}

	// Handle metrics on the DefaultServeMux. We don't serve HTTP requests
	// for clients, only DNS.
	http.Handle("/metrics", promhttp.Handler())

	// Return a 200 on the root, for GCE default health checking :/
	http.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) { resp.WriteHeader(http.StatusOK) })

	// Bring up the DNS udpServer and serve until we get a signal not to.
	go awaitSignal(func() {
		os.Exit(1)
	})
	// TODO(Martin2112): Might need a separate metrics endpoint like CTFE.
	// Bring up the UDP Server and allow time for it to start.
	ch := make(chan bool)
	udpServer := dns.Server{
		Addr:       *metricsEndpoint,
		Net:        "udp",
		TsigSecret: nil,
		NotifyStartedFunc: func() {
			ch <- true
		},
	}

	// Allow a short time for the UDP server to notify us that it is ready.
	go udpServer.ListenAndServe()
	select {
	case res := <-ch:
		glog.Infof("UDP Server has started OK: %v", res)
	case <-time.After(*startupWait):
		glog.Exitf("UDP Server not listening within timeout")
	}

	// Now start the TCP server.
	tcpServer := dns.Server{
		Addr:       *metricsEndpoint,
		Net:        "tcp",
		TsigSecret: nil}
	if err := tcpServer.ListenAndServe(); err != nil {
		glog.Errorf("Failed to setup the TCP DNS Server: %s\n", err.Error())
	}
	glog.Flush()
}

// awaitSignal waits for standard termination signals, then runs the given
// function; it should be run as a separate goroutine.
func awaitSignal(doneFn func()) {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block main and wait for a signal
	sig := <-sigs
	glog.Warningf("Signal received: %v", sig)
	glog.Flush()

	doneFn()
}

func setupDNSHandler(hc *http.Client, baseURI string, cfg *configpb.LogConfig) error {
	uri := fmt.Sprintf("%s/%s", baseURI, cfg.Prefix)
	var opts jsonclient.Options
	dc, err := client.New(uri, hc, opts)
	if err != nil {
		return err
	}
	handler := ctdns.New(cfg, baseURI, dc, hc.Timeout)
	dns.DefaultServeMux.Handle(cfg.DnsZone, handler)
	return nil
}

func readMultiCfg(filename string) (*configpb.LogMultiConfig, error) {
	cfg, err := ctfe.MultiLogConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func readCfg(filename string, backendSpec string) (*configpb.LogMultiConfig, error) {
	cfg, err := ctfe.LogConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	return ctfe.ToMultiLogConfig(cfg, backendSpec), nil
}
