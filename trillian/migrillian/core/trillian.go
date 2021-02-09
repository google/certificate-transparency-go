// Copyright 2018 Google LLC. All Rights Reserved.
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

package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errRetry = errors.New("retry")

// PreorderedLogClient is a means of communicating with a single Trillian
// pre-ordered log tree.
type PreorderedLogClient struct {
	cli    trillian.TrillianLogClient
	treeID int64
	idFunc func(int64, *ct.RawLogEntry) []byte
	prefix string // TODO(pavelkalinnikov): Get rid of this.
}

// NewPreorderedLogClient creates and initializes a pre-ordered log client.
func NewPreorderedLogClient(
	cli trillian.TrillianLogClient,
	tree *trillian.Tree,
	idFuncType configpb.IdentityFunction,
	prefix string,
) (*PreorderedLogClient, error) {
	if tree == nil {
		return nil, errors.New("missing Tree")
	}
	if got, want := tree.TreeType, trillian.TreeType_PREORDERED_LOG; got != want {
		return nil, fmt.Errorf("tree %d is %v, want %v", tree.TreeId, got, want)
	}
	if got, want := tree.GetHashStrategy(), trillian.HashStrategy_RFC6962_SHA256; got != want {
		return nil, fmt.Errorf("hash strategy is %v, want %v", got, want)
	}
	ret := PreorderedLogClient{cli: cli, treeID: tree.TreeId, prefix: prefix}

	switch idFuncType {
	case configpb.IdentityFunction_SHA256_CERT_DATA:
		ret.idFunc = idHashCertData
	case configpb.IdentityFunction_SHA256_LEAF_INDEX:
		ret.idFunc = idHashLeafIndex
	default:
		return nil, fmt.Errorf("unknown identity function: %v", idFuncType)
	}

	return &ret, nil
}

// getRoot returns the current root of the Trillian tree.
func (c *PreorderedLogClient) getRoot(ctx context.Context) (*types.LogRootV1, error) {
	req := trillian.GetLatestSignedLogRootRequest{LogId: c.treeID}
	rsp, err := c.cli.GetLatestSignedLogRoot(ctx, &req)
	if err != nil {
		return nil, err
	} else if rsp == nil || rsp.SignedLogRoot == nil {
		return nil, errors.New("missing SignedLogRoot")
	}
	var logRoot types.LogRootV1
	if err := logRoot.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return nil, err
	}
	return &logRoot, nil
}

// addSequencedLeaves converts a batch of CT log entries into Trillian log
// leaves and submits them to Trillian via AddSequencedLeaves API.
//
// If and while Trillian returns "quota exceeded" errors, the function will
// retry the request with a limited exponential back-off.
//
// Returns an error if Trillian replies with a severe/unknown error.
func (c *PreorderedLogClient) addSequencedLeaves(ctx context.Context, b *scanner.EntryBatch) error {
	// TODO(pavelkalinnikov): Verify range inclusion against the remote STH.
	leaves := make([]*trillian.LogLeaf, len(b.Entries))
	for i, e := range b.Entries {
		var err error
		if leaves[i], err = c.buildLogLeaf(b.Start+int64(i), &e); err != nil {
			return err
		}
	}
	req := trillian.AddSequencedLeavesRequest{LogId: c.treeID, Leaves: leaves}

	// TODO(pavelkalinnikov): Make this strategy configurable.
	bo := backoff.Backoff{
		Min:    1 * time.Second,
		Max:    1 * time.Minute,
		Factor: 3,
		Jitter: true,
	}

	var err error
	bo.Retry(ctx, func() error {
		var rsp *trillian.AddSequencedLeavesResponse
		rsp, err = c.cli.AddSequencedLeaves(ctx, &req)
		switch status.Code(err) {
		case codes.ResourceExhausted: // There was (probably) a quota error.
			end := b.Start + int64(len(b.Entries))
			glog.Errorf("%d: retrying batch [%d, %d) due to error: %v", c.treeID, b.Start, end, err)
			return errRetry
		case codes.OK:
			if rsp == nil {
				err = errors.New("missing AddSequencedLeaves response")
			}
			// TODO(pavelkalinnikov): Check rsp.Results statuses.
			return nil
		default: // There was another (probably serious) error.
			return nil // Stop backing off, and return err as is below.
		}
	})

	return err
}

func (c *PreorderedLogClient) buildLogLeaf(index int64, entry *ct.LeafEntry) (*trillian.LogLeaf, error) {
	rle, err := ct.RawLogEntryFromLeaf(index, entry)
	if err != nil {
		return nil, err
	}

	// Don't return on x509 parsing errors because we want to migrate this log
	// entry as is. But log the error so that it can be flagged by monitoring.
	if _, err = rle.ToLogEntry(); x509.IsFatal(err) {
		glog.Errorf("%s: index=%d: x509 fatal error: %v", c.prefix, index, err)
	} else if err != nil {
		glog.Infof("%s: index=%d: x509 non-fatal error: %v", c.prefix, index, err)
	}
	// TODO(pavelkalinnikov): Verify cert chain if error is nil or non-fatal.

	leafIDHash := c.idFunc(index, rle)
	return &trillian.LogLeaf{
		LeafValue:        entry.LeafInput,
		ExtraData:        entry.ExtraData,
		LeafIndex:        index,
		LeafIdentityHash: leafIDHash[:],
	}, nil
}

func idHashCertData(_ int64, entry *ct.RawLogEntry) []byte {
	hash := sha256.Sum256(entry.Cert.Data)
	return hash[:]
}

func idHashLeafIndex(index int64, _ *ct.RawLogEntry) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(index))
	hash := sha256.Sum256(data)
	return hash[:]
}
