// Copyright 2019 Google LLC. All Rights Reserved.
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

package ctfe

import (
	"context"
	"crypto"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

type testCase struct {
	desc     string
	ctxSetup func(ctx context.Context) context.Context
	ms       MirrorSTHStorage // Only set for mirror getter tests.
	slr      *trillian.GetLatestSignedLogRootResponse
	slrErr   error
	sig      []byte // Only set (and sigErr) for log getter tests.
	sigErr   error
	wantSTH  *ct.SignedTreeHead
	errStr   string
}

// commonTests are valid for both cases, mostly basic parameter checks
// and type / error handling.
func commonTests(t *testing.T) []testCase {
	t.Helper()
	return []testCase{
		{
			desc: "bad quota value",
			ctxSetup: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, remoteQuotaCtxKey, []byte("not a string value"))
			},
			errStr: "incorrect quota",
		},
		{
			desc:   "latest root RPC fails",
			slrErr: errors.New("slr failed"),
			errStr: "slr failed",
		},
		{
			desc:   "nil slr",
			slr:    &trillian.GetLatestSignedLogRootResponse{},
			errStr: "no log root",
		},
		{
			desc:   "bad slr",
			slr:    &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte("not tls encoded")}},
			errStr: "unmarshal root: log_root:\"not tls",
		},
		{
			desc: "bad hash",
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{RootHash: []byte("not a 32 byte hash")}),
			},
			errStr: "bad hash size",
		},
	}
}

// logTests apply only to the LogSTHGetter where things are signed.
func logTests(t *testing.T) []testCase {
	t.Helper()
	return []testCase{
		{
			desc: "signer error",
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{RootHash: []byte("12345678123456781234567812345678")}),
			},
			sigErr: errors.New("not signing that"),
			errStr: "sign tree head: not signing",
		},
		{
			desc: "empty sig",
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{RootHash: []byte("12345678123456781234567812345678")}),
			},
			sig:    []byte{},
			errStr: "sign tree head: <nil>",
		},
		{
			desc: "ok",
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{
						// Ensure response contains all fields needed for the CT STH.
						TreeSize:       12345,
						TimestampNanos: 987654321,
						RootHash:       []byte("12345678123456781234567812345678")}),
			},
			sig: []byte("signedit"),
			wantSTH: &ct.SignedTreeHead{
				Timestamp:      987,
				SHA256RootHash: hashFromString("12345678123456781234567812345678"),
				TreeHeadSignature: ct.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,
						Signature: tls.SignatureAlgorithmFromPubKey(tls.Anonymous),
					},
					Signature: []byte("signedit"),
				},
				TreeSize: 12345,
			},
		},
	}
}

// mirrorTests apply only to the MirrorSTHGetter where sth is read from a store.
func mirrorTests(t *testing.T) []testCase {
	t.Helper()
	return []testCase{
		{
			desc: "bad mirror storage",
			ms: &fakeMirrorSTHStorage{
				err: errors.New("mirror store failed"),
			},
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{
						// Ensure response contains all fields needed for the CT STH.
						TreeSize:       12345,
						TimestampNanos: 987654321,
						RootHash:       []byte("12345678123456781234567812345678")}),
			},
			errStr: "mirror store failed",
		},
		{
			desc: "ok",
			ms: &fakeMirrorSTHStorage{
				sth: &ct.SignedTreeHead{
					Timestamp:      987,
					SHA256RootHash: hashFromString("12345678123456781234567812345678"),
					TreeHeadSignature: ct.DigitallySigned{
						Algorithm: tls.SignatureAndHashAlgorithm{
							Hash:      tls.SHA256,
							Signature: tls.SignatureAlgorithmFromPubKey(tls.Anonymous),
						},
						Signature: []byte("signedit"),
					},
					TreeSize: 12345,
				},
			},
			slr: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: mustMarshalRoot(t,
					&types.LogRootV1{
						// Ensure response contains all fields needed for the CT STH.
						TreeSize:       12345,
						TimestampNanos: 987654321,
						RootHash:       []byte("12345678123456781234567812345678")}),
			},
			wantSTH: &ct.SignedTreeHead{
				Timestamp:      987,
				SHA256RootHash: hashFromString("12345678123456781234567812345678"),
				TreeHeadSignature: ct.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,
						Signature: tls.SignatureAlgorithmFromPubKey(tls.Anonymous),
					},
					Signature: []byte("signedit"),
				},
				TreeSize: 12345,
			},
		},
	}
}

func TestLogSTHGetter(t *testing.T) {
	// Note: Does not test signature cache interaction as this is inside
	// signV1TreeHead and covered by other tests.
	tests := make([]testCase, 0, 30)
	tests = append(tests, commonTests(t)...)
	tests = append(tests, logTests(t)...)

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			rpcCl := mockclient.NewMockTrillianLogClient(ctrl)
			if tc.slr != nil || tc.slrErr != nil {
				rpcCl.EXPECT().GetLatestSignedLogRoot(gomock.Any(), cmpMatcher{&trillian.GetLatestSignedLogRootRequest{LogId: 99}}).Return(tc.slr, tc.slrErr)
			}

			sthg := LogSTHGetter{li: &logInfo{rpcClient: rpcCl, logID: 99, signer: &fakeSigner{sig: tc.sig, err: tc.sigErr}}}
			ctx := context.Background()
			if tc.ctxSetup != nil {
				ctx = tc.ctxSetup(ctx)
			}

			sth, err := sthg.GetSTH(ctx)
			if len(tc.errStr) > 0 {
				if err == nil || !strings.Contains(err.Error(), tc.errStr) {
					t.Errorf("GetSTH()=%v, %v want: nil, err containing %s", sth, err, tc.errStr)
				}
			} else {
				if err != nil || !reflect.DeepEqual(sth, tc.wantSTH) {
					t.Errorf("GetSTH()=%v, %v, want: %v, nil", sth, err, tc.wantSTH)
				}
			}
			ctrl.Finish()
		})
	}
}

func TestMirrorSTHGetter(t *testing.T) {
	// Note: This does not test the operation of MirrorSTHStorage. Implementations
	// of this need their own tests.
	tests := make([]testCase, 0, 30)
	tests = append(tests, commonTests(t)...)
	tests = append(tests, mirrorTests(t)...)

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			rpcCl := mockclient.NewMockTrillianLogClient(ctrl)
			if tc.slr != nil || tc.slrErr != nil {
				rpcCl.EXPECT().GetLatestSignedLogRoot(gomock.Any(), cmpMatcher{&trillian.GetLatestSignedLogRootRequest{LogId: 99}}).Return(tc.slr, tc.slrErr)
			}

			sthg := MirrorSTHGetter{li: &logInfo{rpcClient: rpcCl, logID: 99}, st: tc.ms}
			ctx := context.Background()
			if tc.ctxSetup != nil {
				ctx = tc.ctxSetup(ctx)
			}

			sth, err := sthg.GetSTH(ctx)
			if len(tc.errStr) > 0 {
				if err == nil || !strings.Contains(err.Error(), tc.errStr) {
					t.Errorf("GetSTH()=%v, %v want: nil, err containing %s", sth, err, tc.errStr)
				}
			} else {
				if err != nil || !reflect.DeepEqual(sth, tc.wantSTH) {
					t.Errorf("GetSTH()=%v, %v, want: %v, nil", sth, err, tc.wantSTH)
				}
			}
			ctrl.Finish()
		})
	}
}

func TestFrozenSTHGetter(t *testing.T) {
	sth := &ct.SignedTreeHead{TreeSize: 123, Version: 1}
	f := FrozenSTHGetter{sth: sth}
	// This should always return its canned value and never an error.
	if sth2, err := f.GetSTH(context.Background()); sth2 != sth || err != nil {
		t.Fatalf("FrozenSTHGetter.GetSTH()=%v, %v, want: %v, nil", sth2, err, sth)
	}
}

func TestDefaultMirrorSTHStorage(t *testing.T) {
	s, err := DefaultMirrorSTHFactory{}.NewStorage([32]byte{})
	if err != nil {
		t.Fatalf("NewStorage()=%v, %v, want: no err", s, err)
	}
	// We expect a "not implemented" error from this and nil sth.
	sth, err := s.GetMirrorSTH(context.Background(), 9999)
	if sth != nil || err == nil || !strings.Contains(err.Error(), "not impl") {
		t.Fatalf("MirrorSTHStorage.GetMirrorSTH(): got: %v, %v, want: nil, err containing 'not impl'", sth, err)
	}
}

type fakeSigner struct {
	sig []byte
	err error
}

func (f *fakeSigner) Public() crypto.PublicKey {
	return []byte("this key is public") // This will map to tls.Anonymous.
}

func (f *fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return f.sig, f.err
}

type fakeMirrorSTHStorage struct {
	sth *ct.SignedTreeHead
	err error
}

func (f *fakeMirrorSTHStorage) GetMirrorSTH(ctx context.Context, maxTreeSize int64) (*ct.SignedTreeHead, error) {
	return f.sth, f.err
}

func hashFromString(str string) [32]byte {
	var hash = [32]byte{}
	copy(hash[:], []byte(str))
	return hash
}
