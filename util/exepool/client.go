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

package exepool

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// Client can be used to submit Jobs to a Pool safely and concurrently.
type Client struct {
	pool *Pool
	done bool
}

// Add submits the Job to the Pool which created this Client. It is safe to run
// multiple Adds concurrently. Once submitted, the Job is guaranteed to be run.
//
// It is the caller's responsibility to make sure that the Job doesn't block
// Pool when it Stops (for example, the caller might bake Context into its
// Jobs, and cancel it if they need to terminate the Pool quickly).
//
// Warning: Never call Add after Close, as it can panic.
func (c *Client) Add(ctx context.Context, job Job) error {
	select {
	// Note: This write will panic if the channel is closed. However, this won't
	// happen as soon as there is at least one non-closed Client (including c).
	case c.pool.jobs <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close detaches this Client from the Pool. The call is idempotent. The Client
// must not be used after Close.
func (c *Client) Close() {
	c.pool.closeClient(c)
}

// SyncClient is a wrapper around Client that in addition:
//  - limits the number of simultaneously submitted Jobs
//  - tracks completion of the Jobs, and allows to wait for them
type SyncClient struct {
	c   *Client
	sem *semaphore.Weighted
	wg  sync.WaitGroup
}

// NewSyncClient creates a SyncClient based on the lightweight Client. The
// resulting client limits the number of simultaneously submitted Jobs to
// maxInFlight (but there is no limit if maxInFlight <= 0).
func NewSyncClient(client *Client, maxInFlight int) *SyncClient {
	sc := SyncClient{c: client}
	if maxInFlight > 0 {
		sc.sem = semaphore.NewWeighted(int64(maxInFlight))
	}
	return &sc
}

// Add is like Client.Add, but in addition it will first wait until the number
// of Jobs submitted by this client is below maxInFlight.
func (sc *SyncClient) Add(ctx context.Context, job Job) error {
	if err := sc.acquire(ctx); err != nil {
		return err
	}

	wrapped := Job(func() {
		defer sc.release()
		job()
	})

	err := sc.c.Add(ctx, wrapped)
	if err != nil {
		sc.release()
	}
	return err
}

func (sc *SyncClient) acquire(ctx context.Context) error {
	if sem := sc.sem; sem != nil {
		if err := sem.Acquire(ctx, 1); err != nil {
			return err
		}
	}
	sc.wg.Add(1)
	return nil
}

func (sc *SyncClient) release() {
	if sem := sc.sem; sem != nil {
		sc.sem.Release(1)
	}
	sc.wg.Done()
}

// Wait blocks until there is no Jobs in flight.
func (sc *SyncClient) Wait() {
	sc.wg.Wait()
}

// Close is like Client.Close, but in addition it waits until the Pool
// completes all the Jobs that this client has submitted to it.
func (sc *SyncClient) Close() {
	sc.c.Close()
	sc.Wait()
}
