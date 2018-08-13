// Package exepool provides a pool of parallel executors.
// TODO(pavelkalinnikov): Move it to Trillian repo, and also use there.
package exepool

import (
	"errors"
	"fmt"
	"sync"
)

// Errors that the Pool API might return.
var (
	ErrPoolStopped   = errors.New("pool stopped")
	ErrActiveClients = errors.New("there are active clients")
)

// Job is an arbitrary function that can be run by executors.
type Job func()

// Pool is a collection of parallel executors that can run arbitrary Jobs.
type Pool struct {
	execs int
	jobs  chan Job
	wg    sync.WaitGroup

	mu         sync.Mutex
	clients    int
	chanClosed bool
}

// New creates a new Pool which consists of execs parallel executor goroutines,
// and has a buffer of buf incoming jobs. Note that if buf == 0 then there is
// no buffer, and the Jobs get directly to executors (possibly after waiting).
func New(execs, buf int) (*Pool, error) {
	if execs <= 0 {
		return nil, fmt.Errorf("Num of executors %d <= 0, want > 0", execs)
	} else if buf < 0 {
		return nil, fmt.Errorf("Buffer size %d < 0, want >= 0", buf)
	}
	jobs := make(chan Job, buf)
	return &Pool{execs: execs, jobs: jobs}, nil
}

// NewClient creates a new Client submitting Jobs to this Pool.
func (p *Pool) NewClient() (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.chanClosed {
		return nil, ErrPoolStopped
	}
	p.clients++
	return &Client{pool: p}, nil
}

// closeClient closes a Client created by the NewClient method.
func (p *Pool) closeClient(c *Client) {
	if c.done { // Prevent decreasing the counter twice.
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c.done = true
	p.clients--
}

// Start starts processing the Jobs, and returns.
func (p *Pool) Start() {
	for i, e := 0, p.execs; i < e; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				job()
			}
		}()
	}
}

// Stop waits until all pending Jobs are executed, and permanently stops the
// execution. Stop can only be called if all Clients of this Pool are closed,
// otherwise it will return ErrActiveClients. The Pool must not be used after a
// successful Stop (except for maybe calling Stop again, it is idempotent).
func (p *Pool) Stop() error {
	if err := p.closeIfNoClients(); err != nil {
		return err
	}
	// Now the jobs channel is closed, but the executors might still be running
	// some Jobs, and there might be pending ones if buffer size is > 0. Wait
	// until all the Jobs are drained.
	p.wg.Wait()
	return nil
}

func (p *Pool) closeIfNoClients() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.chanClosed {
		return nil
	} else if p.clients != 0 {
		return ErrActiveClients
	}
	p.chanClosed = true
	close(p.jobs)
	return nil
}
