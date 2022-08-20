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

// The ct_server binary runs the CT personality.
package main

import (
	"context"
	"crypto"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keys/pkcs11"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/tomasen/realip"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/naming/endpoints"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

// Global flags that affect all log instances.
var (
	httpEndpoint       = flag.String("http_endpoint", "localhost:6962", "Endpoint for HTTP (host:port)")
	metricsEndpoint    = flag.String("metrics_endpoint", "", "Endpoint for serving metrics; if left empty, metrics will be visible on --http_endpoint")
	rpcBackend         = flag.String("log_rpc_server", "", "Backend specification; comma-separated list or etcd service name (if --etcd_servers specified). If unset backends are specified in config (as a LogMultiConfig proto)")
	rpcDeadline        = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
	getSTHInterval     = flag.Duration("get_sth_interval", time.Second*180, "Interval between internal get-sth operations (0 to disable)")
	logConfig          = flag.String("log_config", "", "File holding log config in text proto format")
	maxGetEntries      = flag.Int64("max_get_entries", 0, "Max number of entries we allow in a get-entries request (0=>use default 1000)")
	etcdServers        = flag.String("etcd_servers", "", "A comma-separated list of etcd servers")
	etcdHTTPService    = flag.String("etcd_http_service", "trillian-ctfe-http", "Service name to announce our HTTP endpoint under")
	etcdMetricsService = flag.String("etcd_metrics_service", "trillian-ctfe-metrics-http", "Service name to announce our HTTP metrics endpoint under")
	maskInternalErrors = flag.Bool("mask_internal_errors", false, "Don't return error strings with Internal Server Error HTTP responses")
	tracing            = flag.Bool("tracing", false, "If true opencensus Stackdriver tracing will be enabled. See https://opencensus.io/.")
	tracingProjectID   = flag.String("tracing_project_id", "", "project ID to pass to stackdriver. Can be empty for GCP, consult docs for other platforms.")
	tracingPercent     = flag.Int("tracing_percent", 0, "Percent of requests to be traced. Zero is a special case to use the DefaultSampler")
	quotaRemote        = flag.Bool("quota_remote", true, "Enable requesting of quota for IP address sending incoming requests")
	quotaIntermediate  = flag.Bool("quota_intermediate", true, "Enable requesting of quota for intermediate certificates in sumbmitted chains")
	handlerPrefix      = flag.String("handler_prefix", "", "If set e.g. to '/logs' will prefix all handlers that don't define a custom prefix")
	pkcs11ModulePath   = flag.String("pkcs11_module_path", "", "Path to the PKCS#11 module to use for keys that use the PKCS#11 interface")
)

const unknownRemoteUser = "UNKNOWN_REMOTE"

// nolint:staticcheck
func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	keys.RegisterHandler(&keyspb.PEMKeyFile{}, pem.FromProto)
	keys.RegisterHandler(&keyspb.PrivateKey{}, der.FromProto)
	keys.RegisterHandler(&keyspb.PKCS11Config{}, func(ctx context.Context, pb proto.Message) (crypto.Signer, error) {
		if cfg, ok := pb.(*keyspb.PKCS11Config); ok {
			return pkcs11.FromConfig(*pkcs11ModulePath, cfg)
		}
		return nil, fmt.Errorf("pkcs11: got %T, want *keyspb.PKCS11Config", pb)
	})

	if *maxGetEntries > 0 {
		ctfe.MaxGetEntriesAllowed = *maxGetEntries
	}

	var cfg *configpb.LogMultiConfig
	var err error
	// Get log config from file before we start. This is a different proto
	// type if we're using a multi backend configuration (no rpcBackend set
	// in flags). The single-backend config is converted to a multi config so
	// they can be treated the same.
	if len(*rpcBackend) > 0 {
		var cfgs []*configpb.LogConfig
		if cfgs, err = ctfe.LogConfigFromFile(*logConfig); err == nil {
			cfg = ctfe.ToMultiLogConfig(cfgs, *rpcBackend)
		}
	} else {
		cfg, err = ctfe.MultiLogConfigFromFile(*logConfig)
	}

	if err != nil {
		klog.Exitf("Failed to read config: %v", err)
	}

	beMap, err := ctfe.ValidateLogMultiConfig(cfg)
	if err != nil {
		klog.Exitf("Invalid config: %v", err)
	}

	klog.CopyStandardLogTo("WARNING")
	klog.Info("**** CT HTTP Server Starting ****")

	metricsAt := *metricsEndpoint
	if metricsAt == "" {
		metricsAt = *httpEndpoint
	}

	dialOpts := []grpc.DialOption{grpc.WithInsecure()}
	if len(*etcdServers) > 0 {
		// Use etcd to provide endpoint resolution.
		cfg := clientv3.Config{Endpoints: strings.Split(*etcdServers, ","), DialTimeout: 5 * time.Second}
		client, err := clientv3.New(cfg)
		if err != nil {
			klog.Exitf("Failed to connect to etcd at %v: %v", *etcdServers, err)
		}

		httpManager, err := endpoints.NewManager(client, *etcdHTTPService)
		if err != nil {
			klog.Exitf("Failed to create etcd http manager: %v", err)
		}
		metricsManager, err := endpoints.NewManager(client, *etcdMetricsService)
		if err != nil {
			klog.Exitf("Failed to create etcd metrics manager: %v", err)
		}

		etcdHTTPKey := fmt.Sprintf("%s/%s", *etcdHTTPService, *httpEndpoint)
		klog.Infof("Announcing our presence at %v with %+v", etcdHTTPKey, *httpEndpoint)
		httpManager.AddEndpoint(ctx, etcdHTTPKey, endpoints.Endpoint{Addr: *httpEndpoint})

		etcdMetricsKey := fmt.Sprintf("%s/%s", *etcdMetricsService, metricsAt)
		klog.Infof("Announcing our presence in %v with %+v", *etcdMetricsService, metricsAt)
		metricsManager.AddEndpoint(ctx, etcdMetricsKey, endpoints.Endpoint{Addr: metricsAt})

		defer func() {
			klog.Infof("Removing our presence in %v", etcdHTTPKey)
			httpManager.DeleteEndpoint(ctx, etcdHTTPKey)
			klog.Infof("Removing our presence in %v", etcdMetricsKey)
			metricsManager.DeleteEndpoint(ctx, etcdMetricsKey)
		}()
	} else if strings.Contains(*rpcBackend, ",") {
		// This should probably not be used in production. Either use etcd or a gRPC
		// load balancer. It's only used by the integration tests.
		klog.Warning("Multiple RPC backends from flags not recommended for production. Should probably be using etcd or a gRPC load balancer / proxy.")
		res := manual.NewBuilderWithScheme("whatever")
		backends := strings.Split(*rpcBackend, ",")
		addrs := make([]resolver.Address, 0, len(backends))
		for _, backend := range backends {
			addrs = append(addrs, resolver.Address{Addr: backend, Type: resolver.Backend})
		}
		res.InitialState(resolver.State{Addresses: addrs})
		resolver.SetDefaultScheme(res.Scheme())
		dialOpts = append(dialOpts, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`), grpc.WithResolvers(res))
	} else {
		klog.Infof("Using regular DNS resolver")
		dialOpts = append(dialOpts, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))
	}

	// Dial all our log backends.
	clientMap := make(map[string]trillian.TrillianLogClient)
	for _, be := range beMap {
		klog.Infof("Dialling backend: %v", be)
		if len(beMap) == 1 {
			// If there's only one of them we use the blocking option as we can't
			// serve anything until connected.
			dialOpts = append(dialOpts, grpc.WithBlock())
		}
		conn, err := grpc.Dial(be.BackendSpec, dialOpts...)
		if err != nil {
			klog.Exitf("Could not dial RPC server: %v: %v", be, err)
		}
		defer conn.Close()
		clientMap[be.Name] = trillian.NewTrillianLogClient(conn)
	}

	// Allow cross-origin requests to all handlers registered on corsMux.
	// This is safe for CT log handlers because the log is public and
	// unauthenticated so cross-site scripting attacks are not a concern.
	corsMux := http.NewServeMux()
	corsHandler := cors.AllowAll().Handler(corsMux)
	http.Handle("/", corsHandler)

	// Register handlers for all the configured logs using the correct RPC
	// client.
	for _, c := range cfg.LogConfigs.Config {
		inst, err := setupAndRegister(ctx, clientMap[c.LogBackendName], *rpcDeadline, c, corsMux, *handlerPrefix, *maskInternalErrors)
		if err != nil {
			klog.Exitf("Failed to set up log instance for %+v: %v", cfg, err)
		}
		if *getSTHInterval > 0 {
			go inst.RunUpdateSTH(ctx, *getSTHInterval)
		}
	}

	// Return a 200 on the root, for GCE default health checking :/
	corsMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			resp.WriteHeader(http.StatusOK)
		} else {
			resp.WriteHeader(http.StatusNotFound)
		}
	})

	// Export a healthz target.
	corsMux.HandleFunc("/healthz", func(resp http.ResponseWriter, req *http.Request) {
		// TODO(al): Wire this up to tell the truth.
		resp.Write([]byte("ok"))
	})

	if metricsAt != *httpEndpoint {
		// Run a separate handler for metrics.
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			metricsServer := http.Server{Addr: metricsAt, Handler: mux}
			err := metricsServer.ListenAndServe()
			klog.Warningf("Metrics server exited: %v", err)
		}()
	} else {
		// Handle metrics on the DefaultServeMux.
		http.Handle("/metrics", promhttp.Handler())
	}

	// If we're enabling tracing we need to use an instrumented http.Handler.
	var handler http.Handler
	if *tracing {
		handler, err = opencensus.EnableHTTPServerTracing(*tracingProjectID, *tracingPercent)
		if err != nil {
			klog.Exitf("Failed to initialize stackdriver / opencensus tracing: %v", err)
		}
	}

	// Bring up the HTTP server and serve until we get a signal not to.
	srv := http.Server{Addr: *httpEndpoint, Handler: handler}
	shutdownWG := new(sync.WaitGroup)
	go awaitSignal(func() {
		shutdownWG.Add(1)
		defer shutdownWG.Done()
		// Allow 60s for any pending requests to finish then terminate any stragglers
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		defer cancel()
		klog.Info("Shutting down HTTP server...")
		srv.Shutdown(ctx)
		klog.Info("HTTP server shutdown")
	})

	err = srv.ListenAndServe()
	if err != http.ErrServerClosed {
		klog.Warningf("Server exited: %v", err)
	}
	// Wait will only block if the function passed to awaitSignal was called,
	// in which case it'll block until the HTTP server has gracefully shutdown
	shutdownWG.Wait()
	klog.Flush()
}

// awaitSignal waits for standard termination signals, then runs the given
// function; it should be run as a separate goroutine.
func awaitSignal(doneFn func()) {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block main and wait for a signal
	sig := <-sigs
	klog.Warningf("Signal received: %v", sig)
	klog.Flush()

	doneFn()
}

func setupAndRegister(ctx context.Context, client trillian.TrillianLogClient, deadline time.Duration, cfg *configpb.LogConfig, mux *http.ServeMux, globalHandlerPrefix string, maskInternalErrors bool) (*ctfe.Instance, error) {
	vCfg, err := ctfe.ValidateLogConfig(cfg)
	if err != nil {
		return nil, err
	}

	opts := ctfe.InstanceOptions{
		Validated:          vCfg,
		Client:             client,
		Deadline:           deadline,
		MetricFactory:      prometheus.MetricFactory{},
		RequestLog:         new(ctfe.DefaultRequestLog),
		MaskInternalErrors: maskInternalErrors,
	}
	if *quotaRemote {
		klog.Info("Enabling quota for requesting IP")
		opts.RemoteQuotaUser = func(r *http.Request) string {
			var remoteUser = realip.FromRequest(r)
			if len(remoteUser) == 0 {
				return unknownRemoteUser
			}
			return remoteUser
		}
	}
	if *quotaIntermediate {
		klog.Info("Enabling quota for intermediate certificates")
		opts.CertificateQuotaUser = ctfe.QuotaUserForCert
	}
	// Full handler pattern will be of the form "/logs/yyz/ct/v1/add-chain", where "/logs" is the
	// HandlerPrefix and "yyz" is the c.Prefix for this particular log. Use the default
	// HandlerPrefix unless the log config overrides it. The custom prefix in
	// the log configuration intended for use in migration scenarios where logs
	// have an existing URL path that differs from the global one. For example
	// if all new logs are served on "/logs/log/..." and a previously existing
	// log is at "/log/..." this is now supported.
	lhp := globalHandlerPrefix
	if ohPrefix := cfg.OverrideHandlerPrefix; len(ohPrefix) > 0 {
		klog.Infof("Log with prefix: %s is using a custom HandlerPrefix: %s", cfg.Prefix, ohPrefix)
		lhp = "/" + strings.Trim(ohPrefix, "/")
	}
	inst, err := ctfe.SetUpInstance(ctx, opts)
	if err != nil {
		return nil, err
	}
	for path, handler := range inst.Handlers {
		mux.Handle(lhp+path, handler)
	}
	return inst, nil
}
