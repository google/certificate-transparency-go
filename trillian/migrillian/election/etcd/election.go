// Copyright 2017 Google Inc. All Rights Reserved.
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

// Package etcd provides an implementation of master election based on etcd.
package etcd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/migrillian/election"
)

// Election is an implementation of election.Election based on etcd.
type Election struct {
	treeID     int64
	instanceID string
	lockFile   string

	client   *clientv3.Client
	session  *concurrency.Session
	election *concurrency.Election

	ctx    context.Context
	cancel context.CancelFunc
}

// Await blocks until the instance captures mastership. Returns the "master
// context" which remains active until the instance stops being the master, or
// the passed in context is canceled. Returns an error if capturing fails, or
// the passed in context is canceled before mastership is captured.
func (e *Election) Await(ctx context.Context) (context.Context, error) {
	if e.ctx != nil && e.ctx.Err() == nil {
		return e.ctx, nil
	}

	if err := e.election.Campaign(ctx, e.instanceID); err != nil {
		return nil, err
	}

	// Get a channel for notifications of election status (using the cancelable
	// context so that the monitoring goroutine below and the goroutine started
	// by Observe will reliably terminate).
	cctx, cancel := context.WithCancel(ctx)
	ch := e.election.Observe(cctx)

	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case rsp, ok := <-ch:
		if !ok {
			cancel()
			return nil, errors.New("mastership unconfirmed")
		}
		if string(rsp.Kvs[0].Value) != e.instanceID {
			cancel()
			return nil, errors.New("mastership overtaken")
		}
	}

	// At this point we have observed confirmation that we are the master; start
	// a goroutine to monitor for anyone else overtaking us.
	go func() {
		for rsp := range ch {
			if string(rsp.Kvs[0].Value) != e.instanceID {
				glog.Warningf("%d: mastership overtaken", e.treeID)
				break
			}
		}
		glog.Infof("%d: canceling master context", e.treeID)
		cancel()
	}()

	e.ctx, e.cancel = cctx, cancel
	return cctx, nil
}

// Resign cancels the master context and releases mastership for this instance.
// The instance can be elected again using Await.
func (e *Election) Resign(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	return e.election.Resign(ctx)
}

// Close cancels the master context, permanently stops participating in
// election, and releases the resources. It does best effort on resigning
// despite potential cancelation of the passed in context. No other method
// should be called after Close.
func (e *Election) Close(ctx context.Context) error {
	if err := e.Resign(ctx); err != nil {
		glog.Errorf("%d: Resign(): %v", e.treeID, err)
	}
	// Session's Close revokes the underlying lease, which results in removing
	// the election-related keys. This achieves the effect of resignation even if
	// the above Resign call failed (e.g. due to ctx cancelation).
	return e.session.Close()
}

// Factory creates Election instances.
type Factory struct {
	client     *clientv3.Client
	instanceID string
	lockDir    string
}

// NewFactory builds an election factory that uses the given parameters. The
// passed in etcd client should remain valid for the lifetime of the object.
func NewFactory(instanceID string, client *clientv3.Client, lockDir string) *Factory {
	return &Factory{
		client:     client,
		instanceID: instanceID,
		lockDir:    lockDir,
	}
}

// NewElection creates a specific Election instance.
func (f *Factory) NewElection(ctx context.Context, treeID int64) (election.Election, error) {
	// TODO(pavelkalinnikov): Re-create the session if it expires.
	// TODO(pavelkalinnikov): Share the same session between Election instances.
	session, err := concurrency.NewSession(f.client)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd session: %v", err)
	}
	lockFile := fmt.Sprintf("%s/%d", strings.TrimRight(f.lockDir, "/"), treeID)
	election := concurrency.NewElection(session, lockFile)

	el := Election{
		treeID:     treeID,
		instanceID: f.instanceID,
		lockFile:   lockFile,
		client:     f.client,
		session:    session,
		election:   election,
	}
	glog.Infof("Election created: %+v", el)

	return &el, nil
}
