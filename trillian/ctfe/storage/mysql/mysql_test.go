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

package mysql

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIssuanceChainFindByKeySuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	testVal := readTestData(t, "leaf00.chain")
	testKey := sha256.Sum256(testVal)

	issuanceChainMockRows := sqlmock.NewRows([]string{"ChainValue"}).AddRow(testVal)
	mock.ExpectQuery(selectIssuanceChainByKeySQL).WillReturnRows(issuanceChainMockRows)

	storage := mockIssuanceChainStorage(db)
	got, err := storage.FindByKey(context.Background(), testKey[:])
	if err != nil {
		t.Errorf("issuanceChainStorage.FindByKey: %v", err)
	}
	if !bytes.Equal(got, testVal) {
		t.Errorf("got: %v, want: %v", got, testVal)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestIssuanceChainAddSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	tests := setupTestData(t,
		"leaf00.chain",
		"leaf01.chain",
		"leaf02.chain",
	)

	storage := mockIssuanceChainStorage(db)
	for k, v := range tests {
		mock.ExpectExec("INSERT INTO IssuanceChain").WithArgs([]byte(k), v).WillReturnResult(sqlmock.NewResult(1, 1))
		if err := storage.Add(context.Background(), []byte(k), v); err != nil {
			t.Errorf("issuanceChainStorage.Add: %v", err)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func readTestData(t *testing.T, filename string) []byte {
	t.Helper()

	data, err := os.ReadFile("../../../testdata/" + filename)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func setupTestData(t *testing.T, filenames ...string) map[string][]byte {
	t.Helper()

	data := make(map[string][]byte, len(filenames))

	for _, filename := range filenames {
		val := readTestData(t, filename)
		key := sha256.Sum256(val)
		data[string(key[:])] = val
	}

	return data
}

func mockIssuanceChainStorage(db *sql.DB) *IssuanceChainStorage {
	return &IssuanceChainStorage{
		db: db,
	}
}
