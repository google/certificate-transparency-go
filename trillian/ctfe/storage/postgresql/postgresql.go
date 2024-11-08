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

// Package postgresql defines the IssuanceChainStorage type, which implements IssuanceChainStorage interface with FindByKey and Add methods.
package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"k8s.io/klog/v2"
)

const (
	selectIssuanceChainByKeySQL = "SELECT c.ChainValue FROM IssuanceChain AS c WHERE c.IdentityHash = $1"
	insertIssuanceChainSQL      = "INSERT INTO IssuanceChain(IdentityHash, ChainValue) VALUES ($1, $2)"
)

// IssuanceChainStorage is a PostgreSQL implementation of the IssuanceChainStorage interface.
type IssuanceChainStorage struct {
	db *sql.DB
}

// NewIssuanceChainStorage takes the database connection string as the input and return the IssuanceChainStorage.
func NewIssuanceChainStorage(ctx context.Context, dbConn string) *IssuanceChainStorage {
	db, err := open(dbConn)
	if err != nil {
		klog.Exitf(fmt.Sprintf("failed to open database: %v", err))
	}

	return &IssuanceChainStorage{
		db: db,
	}
}

// FindByKey returns the key-value pair of issuance chain by the key.
func (s *IssuanceChainStorage) FindByKey(ctx context.Context, key []byte) ([]byte, error) {
	row := s.db.QueryRowContext(ctx, selectIssuanceChainByKeySQL, key)
	if err := row.Err(); err != nil {
		return nil, err
	}

	var chain []byte
	if err := row.Scan(&chain); err != nil {
		return nil, err
	}

	return chain, nil
}

// Add inserts the key-value pair of issuance chain.
func (s *IssuanceChainStorage) Add(ctx context.Context, key []byte, chain []byte) error {
	_, err := s.db.ExecContext(ctx, insertIssuanceChainSQL, key, chain)
	if err != nil {
		// Ignore duplicated key error.
		var postgresqlErr *pgconn.PgError
		if errors.As(err, &postgresqlErr) && postgresqlErr.Code == pgerrcode.UniqueViolation {
			return nil
		}
		return err
	}

	return nil
}

// open takes the data source name and returns the sql.DB object.
func open(dataSourceName string) (*sql.DB, error) {
	// Verify data source name format.
	conn := strings.Split(dataSourceName, "://")
	if len(conn) != 2 {
		return nil, errors.New("could not parse PostgreSQL data source name")
	}
	if conn[0] != "postgresql" && conn[0] != "postgres" {
		return nil, errors.New("expect data source name to start with postgresql or postgres")
	}

	db, err := sql.Open("pgx", conn[1])
	if err != nil {
		// Don't log data source name as it could contain credentials.
		klog.Errorf("could not open PostgreSQL database, check config: %s", err)
		return nil, err
	}

	return db, nil
}
