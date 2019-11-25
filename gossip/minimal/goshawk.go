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

package minimal

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/certificate-transparency-go/gossip/minimal/configpb"
	"github.com/google/certificate-transparency-go/gossip/minimal/x509ext"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/incident"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"

	ct "github.com/google/certificate-transparency-go"
	logclient "github.com/google/certificate-transparency-go/client"
	logscanner "github.com/google/certificate-transparency-go/scanner"
	hubclient "github.com/google/trillian-examples/gossip/client"
	hubscanner "github.com/google/trillian-examples/gossip/scanner"
)

var verifier = merkle.NewLogVerifier(rfc6962.DefaultHasher)

// Goshawk is an agent that retrieves STHs from a Gossip Hub, either in
// the form of synthetic certificates or more directly as signed blobs. Each
// STH is then checked for consistency against the source log.
type Goshawk struct {
	dests     map[string]*hubScanner // name => scanner
	origins   map[string]*originLog  // URL => log
	fetchOpts FetchOptions
}

// FetchOptions governs the overall hub retrieval behaviour.
type FetchOptions struct {
	// Number of entries to request in one batch from the Log.
	BatchSize int
	// Number of concurrent fetcher workers to run.
	ParallelFetch int
	// Manage hub retrieval state persistence.
	State         ScanStateManager
	FlushInterval time.Duration
	// Mechanism for reporting compliance incidents.  If unset, a
	// LoggingReporter will be used.
	Reporter incident.Reporter
}

// ScanStateManager controls hub scanning state, with the intention of allowing
// scanning to resume where it was left off across restarts etc.
type ScanStateManager interface {
	// GetHubIndex returns the index at which scanning should commence for the given hub URL.
	GetHubIndex(hubURL string) int64
	// UpdateHubIndex indicates that future scanning of the given hub should start from at least nextIndex.
	UpdateHubIndex(hubURL string, nextIndex int64)
	// Flush ensures state is stored.
	Flush(ctx context.Context) error
}

// ScanState holds a (mutex-protected) map of hub URL to next index to scan from.
type ScanState struct {
	Mu   sync.Mutex
	Next map[string]int64
}

// GetHubIndex returns the index at which scanning should commence for the given hub URL.
func (s *ScanState) GetHubIndex(hubURL string) int64 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Next[hubURL]
}

// UpdateHubIndex indicates that future scanning of the given hub should start from at least nextIndex.
func (s *ScanState) UpdateHubIndex(hubURL string, nextIndex int64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	cur := s.Next[hubURL]
	if nextIndex > cur {
		s.Next[hubURL] = nextIndex
	}
}

// memoryStateManager is an implementation of the ScanStateManager interface
// that does not persist any data; it is intended for use as a fallback and in
// testing.
type memoryStateManager struct {
	ScanState
}

// Flush does nothing for a memoryStateManager.
func (m *memoryStateManager) Flush(ctx context.Context) error {
	// No persistent storage.
	return nil
}

// FileStateManager is an implementation of the ScanStateManager interface
// that stores the scan state in a writable flat file.
type FileStateManager struct {
	ScanState
	filename string
}

// NewFileStateManager creates a FileStateManager from the contents of the given
// filename, which can be be empty but should be over-writable.
func NewFileStateManager(filename string) (*FileStateManager, error) {
	f := FileStateManager{
		ScanState: ScanState{Next: make(map[string]int64)},
		filename:  filename,
	}

	if err := f.read(); err != nil {
		return nil, err
	}

	// Check we can immediately write the same contents back.
	if err := f.flush(); err != nil {
		return nil, fmt.Errorf("%s: failed to write contents: %v", filename, err)
	}

	return &f, nil
}

// read restores state from file, and assumes the caller has ensured serialization.
func (f *FileStateManager) read() error {
	file, err := os.Open(f.filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open file for read: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 2 {
			return fmt.Errorf("%s:%d: found unexpected number of fields", f.filename, line)
		}
		index, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return fmt.Errorf("%s:%d: failed to parse index: %v", f.filename, line, err)
		}
		f.ScanState.Next[fields[0]] = index
	}
	return nil
}

// flush stores state to file, and assumes the caller has ensured serialization.
func (f *FileStateManager) flush() error {
	out, err := os.Create(f.filename)
	if err != nil {
		return fmt.Errorf("failed to create state file: %v", err)
	}
	defer out.Close()
	glog.Infof("Flushing scan state to %s", f.filename)
	for key, next := range f.ScanState.Next {
		glog.Infof("  scanState[%q]=%d", key, next)
		fmt.Fprintf(out, "%s\t%d\n", key, next)
	}
	return nil
}

// Flush stores the current contents to disk.
func (f *FileStateManager) Flush(ctx context.Context) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if err := f.flush(); err != nil {
		return fmt.Errorf("failed to flush state: %v", err)
	}
	return nil
}

type originLog struct {
	reporter incident.Reporter
	logConfig
	sigAlgo tls.SignatureAlgorithm

	sths       chan *x509ext.LogSTHInfo
	mu         sync.RWMutex
	currentSTH *ct.SignedTreeHead
}

type hubScanner struct {
	hawk        *Goshawk
	Name        string
	URL         string
	MinInterval time.Duration
	// Hard-configured start index; may be overridden by current scan state.
	cfgStartIndex int64
	fetcher       hubFetcher
}

// hubFetcher retrieves entries from a destination hub of some sort.
type hubFetcher interface {
	fetcher(ctx context.Context, dest *hubScanner, fn func(sthInfo *x509ext.LogSTHInfo)) error
}

// ctHubFetcher retrieves entries from destination hub that is a CT Log with
// synthetic certs in it which contain STHs.
type ctHubFetcher struct {
	Log *logclient.LogClient
}

func (f *ctHubFetcher) fetcher(ctx context.Context, dest *hubScanner, fn func(sthInfo *x509ext.LogSTHInfo)) error {
	fetcherOpts := logscanner.FetcherOptions{
		StartIndex:    dest.hawk.fetchOpts.State.GetHubIndex(dest.URL),
		EndIndex:      0, // Scan up to current STH size.
		BatchSize:     dest.hawk.fetchOpts.BatchSize,
		ParallelFetch: dest.hawk.fetchOpts.ParallelFetch,
		Continuous:    true,
	}
	glog.Infof("Scanning CT Log destination hub %s from %d", dest.Name, fetcherOpts.StartIndex)
	fetcher := logscanner.NewFetcher(f.Log, &fetcherOpts)
	return fetcher.Run(ctx, func(batch logscanner.EntryBatch) {
		glog.V(2).Infof("Scanner(%s): examine batch [%d, %d)", dest.Name, batch.Start, int(batch.Start)+len(batch.Entries))
		for i, entry := range batch.Entries {
			index := batch.Start + int64(i)
			dest.hawk.fetchOpts.State.UpdateHubIndex(dest.URL, index+1)
			rawLogEntry, err := ct.RawLogEntryFromLeaf(index, &entry)
			if err != nil || rawLogEntry == nil {
				glog.Errorf("Scanner(%s): failed to build raw log entry %d: %v", dest.Name, index, err)
				continue
			}
			if rawLogEntry.Leaf.TimestampedEntry.EntryType != ct.X509LogEntryType {
				continue
			}
			entry, err := rawLogEntry.ToLogEntry()
			if x509.IsFatal(err) {
				glog.Errorf("Scanner(%s): failed to parse cert from entry at %d: %v", dest.Name, rawLogEntry.Index, err)
				continue
			}
			if entry.X509Cert == nil {
				glog.Errorf("Internal error: no X509Cert entry in %+v", entry)
				continue
			}
			sthInfo, err := x509ext.LogSTHInfoFromCert(entry.X509Cert)
			if err != nil {
				continue
			}
			glog.Infof("Scanner(%s): process STHInfo for %s from synthetic cert at index %d", dest.Name, sthInfo.LogURL, entry.Index)
			fn(sthInfo)
		}
	})
}

type gossipHubFetcher struct {
	Hub *hubclient.HubClient
}

// gossipHubFetcher retrieves entries from destination pure Gossip hub.
func (f *gossipHubFetcher) fetcher(ctx context.Context, dest *hubScanner, fn func(sthInfo *x509ext.LogSTHInfo)) error {
	fetcherOpts := hubscanner.FetcherOptions{
		StartIndex:    dest.hawk.fetchOpts.State.GetHubIndex(dest.URL),
		EndIndex:      0, // Scan up to current STH size.
		BatchSize:     dest.hawk.fetchOpts.BatchSize,
		ParallelFetch: dest.hawk.fetchOpts.ParallelFetch,
		Continuous:    true,
	}
	glog.Infof("Scanning destination Gossip hub %s from %d", dest.Name, fetcherOpts.StartIndex)
	fetcher := hubscanner.NewFetcher(f.Hub, &fetcherOpts)
	return fetcher.Run(ctx, func(batch hubscanner.EntryBatch) {
		glog.V(2).Infof("Scanner(%s): examine batch [%d, %d)", dest.Name, batch.Start, int(batch.Start)+len(batch.Entries))
		for i, entry := range batch.Entries {
			index := batch.Start + int64(i)
			dest.hawk.fetchOpts.State.UpdateHubIndex(dest.URL, index+1)
			var th ct.TreeHeadSignature
			if rest, err := tls.Unmarshal(entry.BlobData, &th); err != nil {
				glog.Warningf("Scanner(%s): failed to unmarshal BlobData at index %d: %v", dest.Name, index, err)
				continue
			} else if len(rest) > 0 {
				glog.Warningf("Scanner(%s): trailing data (%d bytes) after tree head in BlobData at index %d", dest.Name, len(rest), index)
				continue
			}
			sthInfo := x509ext.LogSTHInfo{
				LogURL:         entry.SourceID,
				Version:        tls.Enum(th.Version),
				TreeSize:       th.TreeSize,
				Timestamp:      th.Timestamp,
				SHA256RootHash: th.SHA256RootHash,
				TreeHeadSignature: ct.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,    // Mandated by RFC 6962 s2.1
						Signature: tls.Anonymous, // Signature algorithm is Log-specific so set later.
					},
					Signature: entry.SourceSignature,
				},
			}

			glog.Infof("Scanner(%s): process STHInfo for %s from Gossip hub entry at index %d", dest.Name, sthInfo.LogURL, index)
			fn(&sthInfo)
		}
	})
}

// NewGoshawkFromFile creates a Goshawk from the given filename, which should
// contain text-protobuf encoded configuration data, together with an optional
// http Client.
func NewGoshawkFromFile(ctx context.Context, filename string, hc *http.Client, fetchOpts FetchOptions) (*Goshawk, error) {
	return NewBoundaryGoshawkFromFile(ctx, filename, hc, hc, fetchOpts)
}

// NewBoundaryGoshawkFromFile creates a Goshawk that uses different
// http.Client instances for source logs and destination hubs, for example to
// allow gossip checking across (some kinds of) network boundaries.
func NewBoundaryGoshawkFromFile(ctx context.Context, filename string, hcLog, hcHub *http.Client, fetchOpts FetchOptions) (*Goshawk, error) {
	cfgBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfgProto configpb.GoshawkConfig
	if txtErr := proto.UnmarshalText(string(cfgBytes), &cfgProto); txtErr != nil {
		if binErr := proto.Unmarshal(cfgBytes, &cfgProto); binErr != nil {
			return nil, fmt.Errorf("failed to parse GoshawkConfig from %q as text protobuf (%v) or binary protobuf (%v)", filename, txtErr, binErr)
		}
	}

	cfg, err := NewBoundaryGoshawk(ctx, &cfgProto, hcLog, hcHub, fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("%s: config error: %v", filename, err)
	}
	return cfg, nil
}

// NewGoshawk creates a Goshawk from the given configuration protobuf and
// optional http client.
func NewGoshawk(ctx context.Context, cfg *configpb.GoshawkConfig, hc *http.Client, fetchOpts FetchOptions) (*Goshawk, error) {
	return NewBoundaryGoshawk(ctx, cfg, hc, hc, fetchOpts)
}

// NewBoundaryGoshawk creates a Goshawk from the given configuration protobuf
// and a pair of http.Client instances for source logs and destination hubs,
// to allow (for example) gossip checking across (some kinds of) network boundaries.
func NewBoundaryGoshawk(_ context.Context, cfg *configpb.GoshawkConfig, hcLog, hcHub *http.Client, fetchOpts FetchOptions) (*Goshawk, error) {
	if len(cfg.DestHub) == 0 {
		return nil, errors.New("no destination hub config found")
	}
	if len(cfg.SourceLog) == 0 {
		return nil, errors.New("no source log config found")
	}
	if cfg.BufferSize < 0 {
		return nil, fmt.Errorf("negative STH buffer size (%d) specified", cfg.BufferSize)
	}
	if fetchOpts.State == nil {
		fetchOpts.State = &memoryStateManager{ScanState{Next: make(map[string]int64)}}
	}
	if fetchOpts.FlushInterval == 0 {
		fetchOpts.FlushInterval = 10 * time.Minute
	}
	if fetchOpts.Reporter == nil {
		fetchOpts.Reporter = &incident.LoggingReporter{}
	}

	hawk := Goshawk{
		dests:     make(map[string]*hubScanner),
		origins:   make(map[string]*originLog),
		fetchOpts: fetchOpts,
	}

	for _, destHub := range cfg.DestHub {
		dest, err := hubScannerFromProto(destHub, hcHub)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dest hub config: %v", err)
		}
		if _, exists := hawk.dests[dest.Name]; exists {
			return nil, fmt.Errorf("duplicate dest hubs for name %q", dest.Name)
		}
		dest.hawk = &hawk
		fetchOpts.State.UpdateHubIndex(dest.URL, dest.cfgStartIndex)
		hawk.dests[dest.Name] = dest
		glog.Infof("configured dest Hub %s to scan at %s starting from %d (%+v)", dest.Name, dest.URL, fetchOpts.State.GetHubIndex(dest.URL), dest)
	}
	seenNames := make(map[string]bool)
	for _, lc := range cfg.SourceLog {
		base, err := logConfigFromProto(lc, hcLog)
		if err != nil {
			return nil, fmt.Errorf("failed to parse source log config: %v", err)
		}
		if _, exists := seenNames[base.Name]; exists {
			return nil, fmt.Errorf("duplicate source logs for name %s", base.Name)
		}
		seenNames[base.Name] = true

		if _, exists := hawk.origins[base.URL]; exists {
			return nil, fmt.Errorf("duplicate source logs for url %s", base.URL)
		}

		// Record the expected signature algorithm for the CT log
		// (either DSA or ECDSA P-256 according to RFC 6962 s2.1.4)
		var sigAlgo tls.SignatureAlgorithm
		switch pkType := base.Log.Verifier.PubKey.(type) {
		case *rsa.PublicKey:
			sigAlgo = tls.RSA
		case *ecdsa.PublicKey:
			sigAlgo = tls.ECDSA
		default:
			return nil, fmt.Errorf("unable to determine public key type %v for name %s", pkType, base.Name)
		}

		hawk.origins[base.URL] = &originLog{
			reporter:  hawk.fetchOpts.Reporter,
			logConfig: *base,
			sigAlgo:   sigAlgo,
			sths:      make(chan *x509ext.LogSTHInfo, cfg.BufferSize),
		}
		glog.Infof("configured source log %s at %s (%+v)", base.Name, base.URL, base)
	}
	return &hawk, nil
}

// Fly starts a collection of goroutines to perform log scanning and STH
// consistency checking. It should be terminated by cancelling the passed-in
// context.
func (hawk *Goshawk) Fly(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(hawk.dests) + len(hawk.origins))

	// If a Scanner fails, cancel everything else.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, dest := range hawk.dests {
		go func(dest *hubScanner) {
			defer wg.Done()
			glog.Infof("starting Scanner(%s)", dest.Name)
			err := dest.Scanner(ctx)
			cancel()
			glog.Infof("finished Scanner(%s): %v", dest.Name, err)
		}(dest)
	}
	for _, origin := range hawk.origins {
		go func(origin *originLog) {
			defer wg.Done()
			glog.Infof("starting STHRetriever(%s)", origin.Name)
			origin.STHRetriever(cctx)
			glog.Infof("finished STHRetriever(%s)", origin.Name)
		}(origin)
	}

	// Flush scan state occasionally in case of abrupt termination.
	go schedule.Every(ctx, hawk.fetchOpts.FlushInterval, func(ctx context.Context) {
		if err := hawk.fetchOpts.State.Flush(ctx); err != nil {
			// Keep going even if we failed to save current state; it
			// just means that the next run will repeat checks that have
			// already been done.
			glog.Errorf("State flush failed: %v", err)
		}
	})

	// The Checkers are consumers at the end of a chain of channels and goroutines,
	// so they need to shut down last to prevent the producers getting blocked.
	var checkerWG sync.WaitGroup
	checkerWG.Add(len(hawk.origins))
	for _, origin := range hawk.origins {
		go func(origin *originLog) {
			defer checkerWG.Done()
			glog.Infof("starting Checker(%s)", origin.Name)
			origin.Checker(ctx)
			glog.Infof("finished Checker(%s)", origin.Name)
		}(origin)
	}

	wg.Wait()
	if err := hawk.fetchOpts.State.Flush(context.Background()); err != nil {
		glog.Errorf("Final state flush failed: %v", err)
	}
	glog.Info("Scanner and STHRetrievers finished, now terminate Checkers")
	for _, origin := range hawk.origins {
		close(origin.sths)
	}
	checkerWG.Wait()
	glog.Info("Checkers finished")
}

// Scanner runs a continuous scan of the destination hub.
func (dest *hubScanner) Scanner(ctx context.Context) error {
	return dest.fetcher.fetcher(ctx, dest, func(sthInfo *x509ext.LogSTHInfo) {
		// Consult the owning Goshawk instance to find the channel that this STH should go down.
		url := string(sthInfo.LogURL)
		origin, ok := dest.hawk.origins[url]
		if !ok {
			glog.Warningf("Scanner(%s): found STH info for unrecognized log at %q", dest.Name, url)
			return
		}
		origin.sths <- sthInfo
	})
}

// Checker processes retrieved STH information, checking against the source log
// (as long is has been long enough since the last check).
func (o *originLog) Checker(ctx context.Context) {
	var lastCheck time.Time
	for sthInfo := range o.sths {
		glog.Infof("Checker(%s): check STH size=%d timestamp=%d", o.Name, sthInfo.TreeSize, sthInfo.Timestamp)
		interval := time.Since(lastCheck)
		if interval < o.MinInterval {
			glog.Infof("Checker(%s): skip validation as too soon (%v) since last check (%v)", o.Name, interval, lastCheck)
			continue
		}
		lastCheck = time.Now()
		if err := o.validateSTH(ctx, sthInfo); err != nil {
			glog.Errorf("Checker(%s): failed to validate STH: %v", o.Name, err)
		}
	}
}

func (o *originLog) validateSTH(ctx context.Context, sthInfo *x509ext.LogSTHInfo) error {
	// Fill in the signature algorithm if it was not present.
	if sthInfo.TreeHeadSignature.Algorithm.Signature == tls.Anonymous {
		sthInfo.TreeHeadSignature.Algorithm.Signature = o.sigAlgo
	}

	// Validate the signature in sthInfo
	sth := ct.SignedTreeHead{
		Version:           ct.Version(sthInfo.Version),
		TreeSize:          sthInfo.TreeSize,
		Timestamp:         sthInfo.Timestamp,
		SHA256RootHash:    sthInfo.SHA256RootHash,
		TreeHeadSignature: sthInfo.TreeHeadSignature,
	}
	if err := o.Log.VerifySTHSignature(sth); err != nil {
		o.reporter.Logf(ctx, o.URL, "STH signature verification failure", "signature",
			fmt.Sprintf("%s%s", o.URL, ct.GetSTHPath),
			"sthInfo=%+v", sthInfo)
		return fmt.Errorf("failed to validate STH signature: %v", err)
	}

	currentSTH := o.getLastSTH()
	if currentSTH == nil {
		glog.Warningf("Checker(%s): no current STH available", o.Name)
		return nil
	}
	first, second := sthInfo.TreeSize, currentSTH.TreeSize
	firstHash, secondHash := sthInfo.SHA256RootHash[:], currentSTH.SHA256RootHash[:]
	if first > second {
		glog.Warningf("Checker(%s): retrieved STH info (size=%d) > current STH (size=%d); reversing check", o.Name, first, second)
		first, second = second, first
		firstHash, secondHash = secondHash, firstHash
	}
	proof, err := o.Log.GetSTHConsistency(ctx, first, second)
	if err != nil {
		o.reporter.Logf(ctx, o.URL, "STH consistency retrieval failure", "get",
			fmt.Sprintf("%s%s?first=%d&second=%d", o.URL, ct.GetSTHConsistencyPath, first, second),
			"err=%s", expandRspError(err))
		return err
	}
	glog.V(2).Infof("Checker(%s): got STH consistency proof %d=>%d of size %d", o.Name, first, second, len(proof))

	if err := verifier.VerifyConsistencyProof(int64(first), int64(second), firstHash, secondHash, proof); err != nil {
		o.reporter.Logf(ctx, o.URL, "STH consistency proof failure", "proof",
			fmt.Sprintf("%s%s?first=%d&second=%d", o.URL, ct.GetSTHConsistencyPath, first, second),
			"hash1=%x hash2=%x proof=%x err=%s", firstHash, secondHash, proof, err)
		return fmt.Errorf("failed to VerifyConsistencyProof(%x @size=%d, %x @size=%d): %v", firstHash, first, secondHash, second, err)
	}
	glog.Infof("Checker(%s): verified that hash %x @%d + proof = hash %x @%d\n", o.Name, firstHash, first, secondHash, second)
	return nil
}

func (o *originLog) STHRetriever(ctx context.Context) {
	schedule.Every(ctx, o.MinInterval, func(ctx context.Context) {
		if sth, err := o.Log.GetSTH(ctx); err != nil {
			glog.Errorf("STHRetriever(%s): failed to get-sth: %v", o.Name, err)
		} else {
			glog.V(2).Infof("STHRetriever(%s): got STH size=%d timestamp=%d", o.Name, sth.TreeSize, sth.Timestamp)
			o.updateSTHIfConsistent(ctx, sth)
		}
		// Wait before retrieving another STH.
		glog.V(2).Infof("STHRetriever(%s): wait for a %s tick", o.Name, o.MinInterval)
	})
	glog.Infof("STHRetriever(%s): termination requested", o.Name)
}

func (o *originLog) updateSTHIfConsistent(ctx context.Context, sth *ct.SignedTreeHead) {
	currentSTH := o.getLastSTH()
	if currentSTH != nil {
		first, firstHash := currentSTH.TreeSize, currentSTH.SHA256RootHash[:]
		second, secondHash := sth.TreeSize, sth.SHA256RootHash[:]
		proof, err := o.Log.GetSTHConsistency(ctx, first, second)
		if err != nil {
			glog.Errorf("STHRetriever(%s): failed to get-sth-consistency(%d, %d): %v", o.Name, first, second, err)
			return
		}
		glog.V(2).Infof("STHRetriever(%s): got STH consistency proof %d=>%d of size %d", o.Name, first, second, len(proof))
		if err := verifier.VerifyConsistencyProof(int64(first), int64(second), firstHash, secondHash, proof); err != nil {
			o.reporter.Logf(ctx, o.URL, "STH consistency proof failure", "proof",
				fmt.Sprintf("%s%s?first=%d&second=%d", o.URL, ct.GetSTHConsistencyPath, first, second),
				"hash1=%x hash2=%x proof=%x err=%s", firstHash, secondHash, proof, err)
			glog.Errorf("STHRetriever(%s): failed to VerifyConsistencyProof(%x @size=%d, %x @size=%d): %v", o.Name, firstHash, first, secondHash, second, err)
			return
		}
	}
	// We have a consistency proof from currentSTH -> sth, so update to the latter.
	o.updateSTH(currentSTH, sth)
}

func (o *originLog) updateSTH(fromSTH, toSTH *ct.SignedTreeHead) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if fromSTH != o.currentSTH {
		// The current STH has changed along the way, so this fromSTH -> toSTH update shouldn't
		// be applied.
		glog.Infof("STHRetriever(%s): skip STH update size=%d=>size=%d as current STH doesn't match (size=%d)", o.Name, fromSTH.TreeSize, toSTH.TreeSize, o.currentSTH.TreeSize)
		return
	}
	if o.currentSTH == nil || toSTH.TreeSize > o.currentSTH.TreeSize {
		glog.V(1).Infof("STHRetriever(%s): update tip STH to size=%d timestamp=%d", o.Name, toSTH.TreeSize, toSTH.Timestamp)
		o.currentSTH = toSTH
	}
}

func (o *originLog) getLastSTH() *ct.SignedTreeHead {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.currentSTH
}
