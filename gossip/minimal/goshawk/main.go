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

// The goshawk binary scans a destination log for gossiped STH values
// and checks consistency against the source logs.
package main

import (
	"context"
	"database/sql"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/gossip/minimal"
	"github.com/google/certificate-transparency-go/gossip/minimal/mysql"

	incidentmysql "github.com/google/monologue/incident/mysql"

	// Load MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

var (
	config           = flag.String("config", "", "File holding log configuration in text proto format")
	batchSize        = flag.Int("batch_size", 1000, "Max number of entries to request per call to get-entries")
	parallelFetch    = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
	mySQLIncidentURI = flag.String("incident_mysql_uri", "monologuetest:soliloquy@tcp(127.0.0.1:3306)/monologuetest", "Connection URI for MySQL database used to hold incident details")
	mySQLStateURI    = flag.String("state_mysql_uri", "cttest:beeblebrox@tcp(127.0.0.1:3306)/cttest", "Connection URI for MySQL database used to hold persistent state")
	stateFile        = flag.String("state", "", "Writable file to hold persistent state")
	stateFlush       = flag.Duration("flush_state", 10*time.Minute, "Interval between persistent state flushes")
)

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fetchOpts := minimal.FetchOptions{
		BatchSize:     *batchSize,
		ParallelFetch: *parallelFetch,
		FlushInterval: *stateFlush,
	}
	if len(*stateFile) > 0 {
		glog.Infof("State will be persisted to %s", *stateFile)
		var err error
		fetchOpts.State, err = minimal.NewFileStateManager(*stateFile)
		if err != nil {
			glog.Exitf("Failed to create file-based state manager: %v", err)
		}
	} else if len(*mySQLStateURI) > 0 {
		glog.Infof("State will be persisted to %s", *mySQLStateURI)
		db, err := sql.Open("mysql", *mySQLStateURI)
		if err != nil {
			glog.Exitf("Failed to open MySQL state database: %v", err)
		}
		if _, err := db.ExecContext(ctx, "SET sql_mode = 'STRICT_ALL_TABLES'"); err != nil {
			glog.Warningf("Failed to set strict mode on MySQL db: %s", err)
		}
		fetchOpts.State, err = mysql.NewStateManager(ctx, db)
		if err != nil {
			glog.Exitf("Failed to create MySQL-based state manager: %v", err)
		}
	}
	if len(*mySQLIncidentURI) > 0 {
		glog.Infof("Incidents will be stored in %s", *mySQLIncidentURI)
		db, err := sql.Open("mysql", *mySQLIncidentURI)
		if err != nil {
			glog.Exitf("Failed to open MySQL incident database: %v", err)
		}
		if _, err := db.ExecContext(ctx, "SET sql_mode = 'STRICT_ALL_TABLES'"); err != nil {
			glog.Warningf("Failed to set strict mode on MySQL incident db: %s", err)
		}

		fetchOpts.Reporter, err = incidentmysql.NewMySQLReporter(ctx, db, "goshawk")
		if err != nil {
			glog.Exitf("Failed to create MySQL-based incident reporter: %v", err)
		}
	}

	hawk, err := minimal.NewGoshawkFromFile(ctx, *config, nil, fetchOpts)
	if err != nil {
		glog.Exitf("Failed to load --config: %v", err)
	}

	glog.CopyStandardLogTo("WARNING")
	glog.Info("**** Goshawk Starting ****")

	go awaitSignal(func() {
		cancel()
	})

	hawk.Fly(ctx)

	glog.Infof("Stopping server, about to exit")
	glog.Flush()

	// Give things a few seconds to tidy up
	time.Sleep(time.Second * 3)
}

// awaitSignal waits for standard termination signals, then runs the given
// function; it should be run as a separate goroutine.
func awaitSignal(doneFn func()) {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block and wait for a signal
	sig := <-sigs
	glog.Warningf("Signal received: %v", sig)
	glog.Flush()

	doneFn()
}
