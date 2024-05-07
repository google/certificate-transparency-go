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

// Package mysql defines the IssuanceChainStorage type, which implements IssuanceChainStorage interface with FindByKey and Add methods.
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"k8s.io/klog/v2"

	"github.com/go-sql-driver/mysql"
)

const (
	selectIssuanceChainByKeySQL = "SELECT c.ChainValue FROM IssuanceChain AS c WHERE c.IdentityHash = ?"
	insertIssuanceChainSQL      = "INSERT INTO IssuanceChain(IdentityHash, ChainValue) VALUES (?, ?)"
)

type IssuanceChainStorage struct {
	db *sql.DB
}

// NewIssuanceChainStorage takes the database connection string as the input and return the IssuanceChainStorage.
func NewIssuanceChainStorage(ctx context.Context, dbConn string) *IssuanceChainStorage {
	conn := strings.Split(dbConn, "://")

	db, err := open(ctx, conn[1])
	if err != nil {
		klog.Errorf("failed to open database: %v", err)
		return nil
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
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return nil
		}
		return err
	}

	return nil
}

// open takes the data source name and returns the sql.DB object.
func open(ctx context.Context, dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		// Don't log data source name as it could contain credentials
		klog.Warningf("Could not open MySQL database, check config: %s", err)
		return nil, err
	}

	if _, err := db.ExecContext(ctx, "SET sql_mode = 'STRICT_ALL_TABLES'"); err != nil {
		klog.Warningf("Failed to set strict mode on mysql db: %s", err)
		return nil, err
	}

	return db, nil
}
