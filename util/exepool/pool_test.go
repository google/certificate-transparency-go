package exepool

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewPool(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		execs   int
		buf     int
		wantErr string
	}{
		{desc: "neg-execs", execs: -10, wantErr: "Num of executors -10 <= 0"},
		{desc: "zero-execs", execs: 0, wantErr: "Num of executors 0 <= 0"},
		{desc: "neg-buf", execs: 1, buf: -10, wantErr: "Buffer size -10 < 0"},
		{desc: "ok-no-buf", execs: 3},
		{desc: "ok-buf", execs: 2, buf: 10},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			pool, err := New(tc.execs, tc.buf)
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("New(): err=%v, want err containing %v", err, tc.wantErr)
			} else if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("New(): err=%v, want nil", err)
			}
			if err != nil {
				return
			}
			if pool == nil {
				t.Fatalf("Pool is nil")
			}

			pool.Start()
			if err := pool.Stop(); err != nil {
				t.Errorf("Stop(): %v", err)
			}
		})
	}
}

func TestPoolStop(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		clients int
		closed  int
		wantErr error
	}{
		{desc: "no-clients"},
		{desc: "1-not-closed", clients: 1, wantErr: ErrActiveClients},
		{desc: "many-not-closed", clients: 20, wantErr: ErrActiveClients},
		{desc: "1-closed", clients: 1, closed: 1},
		{desc: "some-not-closed", clients: 20, closed: 11, wantErr: ErrActiveClients},
		{desc: "almost-all-closed", clients: 20, closed: 19, wantErr: ErrActiveClients},
		{desc: "all-closed", clients: 20, closed: 20},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			pool, err := New(5, 0)
			if err != nil {
				t.Fatalf("pool.New(): %v", err)
			}
			pool.Start()

			clients := make([]*Client, tc.clients)
			for i := 0; i < tc.clients; i++ {
				var err error
				clients[i], err = pool.NewClient()
				if err != nil {
					t.Fatalf("NewClient(): %v", err)
				}
			}

			for i := 0; i < tc.closed; i++ {
				clients[i].Close()
				clients[i].Close()
				clients[i].Close() // Also test idempotence.
			}
			if err, want := pool.Stop(), tc.wantErr; err != want {
				t.Errorf("Stop(): err=%v, want %v", err, want)
			}

			// Now close the rest of the clients, the Pool should become stoppable.
			for i := tc.closed; i < tc.clients; i++ {
				clients[i].Close()
			}
			if err := pool.Stop(); err != nil {
				t.Errorf("Stop(): err=%v, want nil", err)
			}

			// Make sure we can't add clients after stopping the Pool.
			if _, err := pool.NewClient(); err != ErrPoolStopped {
				t.Errorf("NewClient(): err=%v, want %v", err, ErrPoolStopped)
			}
		})
	}
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	pool, err := New(10, 0)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	pool.Start()

	cli, err := pool.NewClient()
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}

	var sum int32
	for i := int32(1); i <= 20; i++ {
		i := i
		cli.Add(ctx, Job(func() {
			atomic.AddInt32(&sum, i)
		}))
	}
	cli.Close()
	if err := pool.Stop(); err != nil {
		t.Errorf("Stop(): %v", err)
	}

	if got, want := sum, int32(210); got != want {
		t.Errorf("sum=%d, want %d", got, want)
	}
}

func TestSyncClient(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		execs       int
		buf         int
		maxInFlight int
		blockedJobs int
	}{
		{desc: "no-in-flight-limit", execs: 10, buf: 0, maxInFlight: 0, blockedJobs: 10},
		{desc: "no-in-flight-limit-buf", execs: 10, buf: 7, maxInFlight: 0, blockedJobs: 17},
		{desc: "max-in-flight-5", execs: 10, buf: 0, maxInFlight: 5, blockedJobs: 5},
		{desc: "max-in-flight-5-buf", execs: 3, buf: 7, maxInFlight: 5, blockedJobs: 5},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			pool, err := New(tc.execs, tc.buf)
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			pool.Start()
			defer pool.Stop()

			cli, err := pool.NewClient()
			if err != nil {
				t.Fatalf("NewClient(): %v", err)
			}
			scli := NewSyncClient(cli, tc.maxInFlight)

			// Run max allowed number of blocking jobs.
			ctx1, cancel1 := context.WithCancel(ctx)
			for i := 0; i < tc.blockedJobs; i++ {
				scli.Add(ctx, Job(func() {
					<-ctx1.Done()
				}))
			}

			// At this point there is no quota/executors/buffer for accepting a new
			// Job, so Add should block and return with timeout.
			done := false
			ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Millisecond)
			job := Job(func() { done = true })
			if err := scli.Add(ctx2, job); err != context.DeadlineExceeded {
				t.Errorf("err=%v, want %v", err, context.DeadlineExceeded)
			}
			if done {
				t.Error("Unexepected Job completion")
			}
			cancel2()

			cancel1()
			// Now all the blocking Jobs should exit pretty quickly, and we'll be
			// able to submit the same Job.
			if err := scli.Add(ctx, job); err != nil {
				t.Errorf("err=%v, want nil", err)
			}
			// But we don't know whether it is completed util we wait for it.
			scli.Close()

			if !done {
				t.Error("Exepected Job completion")
			}
		})
	}
}
