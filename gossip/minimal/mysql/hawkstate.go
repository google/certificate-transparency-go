// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package mysql provides a MySQL based implementation of persistent
// state management for the goshawk tool.
package mysql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/gossip/minimal"
)

// NewStateManager creates a ScanStateManager that stores its state in the given
// database.
func NewStateManager(ctx context.Context, db *sql.DB) (minimal.ScanStateManager, error) {
	m := mysqlStateManager{ScanState: minimal.ScanState{}, db: db}
	if err := m.restore(ctx); err != nil {
		return nil, err
	}
	return &m, nil
}

// restore retrieves state from the database, and assumes the caller has ensured serialization.
func (m *mysqlStateManager) restore(ctx context.Context) error {
	tx, err := m.db.BeginTx(ctx, nil /* opts */)
	if err != nil {
		return fmt.Errorf("failed to create state transaction: %v", err)
	}
	defer tx.Commit()
	rows, err := tx.QueryContext(ctx, "SELECT HubURL, NextIndex FROM HubNext;")
	if err != nil {
		return fmt.Errorf("failed to query state rows: %v", err)
	}
	defer rows.Close()

	glog.Info("Reading scan state from DB")
	m.ScanState.Next = make(map[string]int64)
	for rows.Next() {
		var hubURL string
		var nextIndex int64
		if err := rows.Scan(&hubURL, &nextIndex); err != nil {
			return fmt.Errorf("failed to scan state row: %v", err)
		}
		glog.Infof("  scanState[%q]=%d", hubURL, nextIndex)
		m.ScanState.Next[hubURL] = nextIndex
	}
	return nil
}

type mysqlStateManager struct {
	minimal.ScanState
	db *sql.DB
}

func (m *mysqlStateManager) Flush(ctx context.Context) error {
	m.Mu.Lock()
	defer m.Mu.Unlock()

	tx, err := m.db.BeginTx(ctx, nil /* opts */)
	if err != nil {
		return fmt.Errorf("failed to create state transaction: %v", err)
	}
	defer tx.Commit()

	glog.Info("Flushing scan state to DB")
	for url, index := range m.ScanState.Next {
		glog.Infof("  scanState[%q]=%d", url, index)
		_, err = tx.ExecContext(ctx, "REPLACE INTO HubNext(HubURL, NextIndex) VALUES (?, ?);", url, index)
		if err != nil {
			return fmt.Errorf("failed to store row Next[%s]=%d: %v", url, index, err)
		}
	}
	return nil
}
