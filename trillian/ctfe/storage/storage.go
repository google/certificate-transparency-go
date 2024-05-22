// Copyright 2024 Google LLC
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

// Package storage defines the IssuanceChainStorage type, which allows different storage implementation for the key-value pairs of issuance chains.
package storage

import (
	"context"
	"errors"
	"strings"

	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/ctfe/storage/mysql"
)

// IssuanceChainStorage is an interface which allows CTFE binaries to use different storage implementations for issuance chains.
type IssuanceChainStorage interface {
	// FindByKey returns the issuance chain associated with the provided key.
	FindByKey(ctx context.Context, key []byte) ([]byte, error)

	// Add inserts the key-value pair of issuance chain.
	Add(ctx context.Context, key []byte, chain []byte) error
}

// NewIssuanceChainStorage returns nil for Trillian gRPC or mysql.IssuanceChainStorage when MySQL is the prefix in database connection string.
func NewIssuanceChainStorage(ctx context.Context, backend configpb.LogConfig_IssuanceChainStorageBackend, dbConn string) (IssuanceChainStorage, error) {
	switch backend {
	case configpb.LogConfig_ISSUANCE_CHAIN_STORAGE_BACKEND_TRILLIAN_GRPC:
		return nil, nil
	case configpb.LogConfig_ISSUANCE_CHAIN_STORAGE_BACKEND_CTFE:
		if strings.HasPrefix(dbConn, "mysql") {
			return mysql.NewIssuanceChainStorage(ctx, dbConn), nil
		} else {
			return nil, errors.New("failed to initialise IssuanceChainService due to unsupported driver in CTFE storage connection string")
		}
	}

	return nil, errors.New("unsupported issuance chain storage backend")
}
