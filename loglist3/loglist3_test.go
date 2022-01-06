// Copyright 2022 Google LLC. All Rights Reserved.
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

package loglist3

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// mustParseTime is helper func
func mustParseTime(format string, sTime string) time.Time {
	tm, e := time.Parse(format, sTime)
	if e != nil {
		log.Fatal(e)
	}
	return tm.UTC()
}

var sampleLogList = LogList{
	Version:          "1.1.1c",
	LogListTimestamp: mustParseTime(time.UnixDate, "Fri Dec 3 11:06:00 UTC 2021"),
	Operators: []*Operator{
		{
			Name:  "Google",
			Email: []string{"google-ct-logs@googlegroups.com"},
			Logs: []*Log{
				{
					Description: "Google 'Aviator' log",
					LogID:       deb64("aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q="),
					Key:         deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q=="),
					URL:         "https://ct.googleapis.com/aviator/",
					MMD:         86400,
					State: &LogStates{
						ReadOnly: &ReadOnlyLogState{
							LogState: LogState{Timestamp: time.Unix(1480512258, 330000000).UTC()},
							FinalTreeHead: TreeHead{
								TreeSize:       46466472,
								SHA256RootHash: deb64("LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA="),
							},
						},
					},
					TemporalInterval: &TemporalInterval{
						StartInclusive: mustParseTime(time.UnixDate, "Fri Mar 7 11:06:00 UTC 2014"),
						EndExclusive:   mustParseTime(time.UnixDate, "Sat Mar 7 12:00:00 UTC 2015"),
					},
					DNS: "aviator.ct.googleapis.com",
				},
				{
					Description: "Google 'Icarus' log",
					LogID:       deb64("KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg="),
					Key:         deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA=="),
					URL:         "https://ct.googleapis.com/icarus/",
					MMD:         86400,
					State: &LogStates{
						Usable: &LogState{
							Timestamp: mustParseTime(time.RFC3339, "2018-02-27T00:00:00Z"),
						},
					},
					DNS: "icarus.ct.googleapis.com",
				},
				{
					Description: "Google 'Racketeer' log",
					LogID:       deb64("7kEv4llINIlh4vPgjGgugT7A/3cLbXUXF2OvMBT/l2g="),
					// Key value chosed to have a hash that starts ee4... (specifically ee412fe25948348961e2f3e08c682e813ec0ff770b6d75171763af3014ff9768)
					Key: deb64("Hy2TPTZ2yq9ASMmMZiB9SZEUx5WNH5G0Ft5Tm9vKMcPXA+ic/Ap3gg6fXzBJR8zLkt5lQjvKMdbHYMGv7yrsZg=="),
					URL: "https://ct.googleapis.com/racketeer/",
					MMD: 86400,
					DNS: "racketeer.ct.googleapis.com",
				},
				{
					Description: "Google 'Rocketeer' log",
					LogID:       deb64("7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs="),
					Key:         deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
					URL:         "https://ct.googleapis.com/rocketeer/",
					MMD:         86400,
					DNS:         "rocketeer.ct.googleapis.com",
				},
				{
					Description: "Google 'Argon2020' log",
					LogID:       deb64("sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4="),
					Key:         deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA=="),
					URL:         "https://ct.googleapis.com/logs/argon2020/",
					DNS:         "argon2020.ct.googleapis.com",
					MMD:         86400,
					State: &LogStates{
						Qualified: &LogState{
							Timestamp: mustParseTime(time.RFC3339, "2018-02-27T00:00:00Z"),
						},
					},
					TemporalInterval: &TemporalInterval{
						StartInclusive: mustParseTime(time.RFC3339, "2020-01-01T00:00:00Z"),
						EndExclusive:   mustParseTime(time.RFC3339, "2021-01-01T00:00:00Z"),
					},
				},
			},
		},
		{
			Name:  "Bob's CT Log Shop",
			Email: []string{"bob@example.com"},
			Logs: []*Log{
				{
					Description: "Bob's Dubious Log",
					LogID:       deb64("zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA="),
					Key:         deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA=="),
					URL:         "https://log.bob.io",
					MMD:         86400,
					State: &LogStates{
						Retired: &LogState{
							Timestamp: time.Unix(1460678400, 0).UTC(),
						},
					},
					TemporalInterval: &TemporalInterval{
						StartInclusive: mustParseTime(time.UnixDate, "Fri Nov 7 12:00:00 UTC 2014"),
						EndExclusive:   mustParseTime(time.UnixDate, "Sat Mar 7 12:00:00 UTC 2015"),
					},
					DNS: "dubious-bob.ct.googleapis.com",
					PreviousOperators: []*PreviousOperator{
						{
							Name:    "Alice's Shady Log",
							EndTime: mustParseTime(time.UnixDate, "Thu Nov 6 12:00:00 UTC 2014"),
						},
					},
				},
			},
		},
	},
}

func TestJSONMarshal(t *testing.T) {
	var tests = []struct {
		name          string
		in            LogList
		want, wantErr string
	}{
		{
			name: "MultiValid",
			in:   sampleLogList,
			want: `{"version":"1.1.1c","log_list_timestamp":"2021-12-03T11:06:00Z","operators":[` +
				`{"name":"Google","email":["google-ct-logs@googlegroups.com"],"logs":[` +
				`{"description":"Google 'Aviator' log","log_id":"aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==","url":"https://ct.googleapis.com/aviator/","dns":"aviator.ct.googleapis.com","mmd":86400,"state":{"readonly":{"timestamp":"2016-11-30T13:24:18.33Z","final_tree_head":{"sha256_root_hash":"LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA=","tree_size":46466472}}},"temporal_interval":{"start_inclusive":"2014-03-07T11:06:00Z","end_exclusive":"2015-03-07T12:00:00Z"}},` +
				`{"description":"Google 'Icarus' log","log_id":"KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==","url":"https://ct.googleapis.com/icarus/","dns":"icarus.ct.googleapis.com","mmd":86400,"state":{"usable":{"timestamp":"2018-02-27T00:00:00Z"}}},` +
				`{"description":"Google 'Racketeer' log","log_id":"7kEv4llINIlh4vPgjGgugT7A/3cLbXUXF2OvMBT/l2g=","key":"Hy2TPTZ2yq9ASMmMZiB9SZEUx5WNH5G0Ft5Tm9vKMcPXA+ic/Ap3gg6fXzBJR8zLkt5lQjvKMdbHYMGv7yrsZg==","url":"https://ct.googleapis.com/racketeer/","dns":"racketeer.ct.googleapis.com","mmd":86400},` +
				`{"description":"Google 'Rocketeer' log","log_id":"7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==","url":"https://ct.googleapis.com/rocketeer/","dns":"rocketeer.ct.googleapis.com","mmd":86400},` +
				`{"description":"Google 'Argon2020' log","log_id": "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=","key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==","url":"https://ct.googleapis.com/logs/argon2020/","dns":"argon2020.ct.googleapis.com","mmd":86400,"state":{"qualified":{"timestamp":"2018-02-27T00:00:00Z"}},"temporal_interval":{"start_inclusive":"2020-01-01T00:00:00Z","end_exclusive":"2021-01-01T00:00:00Z"}}]},` +
				`{"name":"Bob's CT Log Shop","email":["bob@example.com"],"logs":[` +
				`{"description":"Bob's Dubious Log","log_id":"zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==","url":"https://log.bob.io","dns":"dubious-bob.ct.googleapis.com","mmd":86400,"previous_operators":[ {"name":"Alice's Shady Log","end_time":"2014-11-06T12:00:00Z"}],"state":{"retired":{"timestamp":"2016-04-15T00:00:00Z"}},"temporal_interval":{"start_inclusive":"2014-11-07T12:00:00Z","end_exclusive":"2015-03-07T12:00:00Z"}}]}]}`,
		},
	}

	const jsonPrefix = ""
	const jsonIndent = "  "

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := json.MarshalIndent(&test.in, jsonPrefix, jsonIndent)
			if err != nil {
				if test.wantErr == "" {
					t.Errorf("json.Marshal()=nil,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("json.Marshal()=nil,%v; want nil,err containing %q", err, test.wantErr)
				}
				return
			}
			if test.wantErr != "" {
				t.Errorf("json.Marshal()=%q,nil; want nil,err containing %q", got, test.wantErr)
			}
			// Format `test.want` in the same way as `got`
			var wantIndented bytes.Buffer
			if err := json.Indent(&wantIndented, []byte(test.want), jsonPrefix, jsonIndent); err != nil {
				t.Fatalf("json.Indent(test.want) = %q, want nil", err)
			}
			dmp := diffmatchpatch.New()
			if diffs := dmp.DiffMain(wantIndented.String(), string(got), false); len(diffs) > 1 {
				t.Errorf("json.Marshal(): diff \n%s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestFindLogByName(t *testing.T) {
	var tests = []struct {
		name, in string
		want     int
	}{
		{name: "Single", in: "Dubious", want: 1},
		{name: "SingleDifferentCase", in: "DUBious", want: 1},
		{name: "Multiple", in: "Google", want: 5},
		{name: "None", in: "Llamalog", want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := sampleLogList.FindLogByName(test.in)
			if len(got) != test.want {
				t.Errorf("len(FindLogByName(%q)=%d, want %d", test.in, len(got), test.want)
			}
		})
	}
}

func TestFindLogByURL(t *testing.T) {
	var tests = []struct {
		name, in, want string
	}{
		{name: "NotFound", in: "nowhere.com"},
		{name: "Found//", in: "https://ct.googleapis.com/icarus/", want: "Google 'Icarus' log"},
		{name: "Found./", in: "https://ct.googleapis.com/icarus", want: "Google 'Icarus' log"},
		{name: "Found/.", in: "https://log.bob.io/", want: "Bob's Dubious Log"},
		{name: "Found..", in: "https://log.bob.io", want: "Bob's Dubious Log"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := sampleLogList.FindLogByURL(test.in)
			got := ""
			if l != nil {
				got = l.Description
			}
			if got != test.want {
				t.Errorf("FindLogByURL(%q)=%q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestFindLogByKeyhash(t *testing.T) {
	var tests = []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "NotFound",
			in:   []byte{0xaa, 0xbb, 0xcc},
		},
		{
			name: "FoundRocketeer",
			in: []byte{
				0xee, 0x4b, 0xbd, 0xb7, 0x75, 0xce, 0x60, 0xba, 0xe1, 0x42, 0x69, 0x1f, 0xab, 0xe1, 0x9e, 0x66,
				0xa3, 0x0f, 0x7e, 0x5f, 0xb0, 0x72, 0xd8, 0x83, 0x00, 0xc4, 0x7b, 0x89, 0x7a, 0xa8, 0xfd, 0xcb,
			},
			want: "Google 'Rocketeer' log",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hash [sha256.Size]byte
			copy(hash[:], test.in)
			l := sampleLogList.FindLogByKeyHash(hash)
			got := ""
			if l != nil {
				got = l.Description
			}
			if got != test.want {
				t.Errorf("FindLogByKeyHash(%x)=%q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestFindLogByKeyhashPrefix(t *testing.T) {
	var tests = []struct {
		name, in string
		want     []string
	}{
		{
			name: "NotFound",
			in:   "aabbcc",
			want: []string{},
		},
		{
			name: "FoundRocketeer",
			in:   "ee4b",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundRocketeerOdd",
			in:   "ee4bb",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundMultiple",
			in:   "ee4",
			want: []string{"Google 'Racketeer' log", "Google 'Rocketeer' log"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := sampleLogList.FindLogByKeyHashPrefix(test.in)
			got := make([]string, len(logs))
			for i, l := range logs {
				got[i] = l.Description
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("FindLogByKeyHash(%x)=%q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestFindLogByKey(t *testing.T) {
	var tests = []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "NotFound",
			in:   []byte{0xaa, 0xbb, 0xcc},
		},
		{
			name: "FoundRocketeer",
			in:   deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
			want: "Google 'Rocketeer' log",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := sampleLogList.FindLogByKey(test.in)
			got := ""
			if l != nil {
				got = l.Description
			}
			if got != test.want {
				t.Errorf("FindLogByKey(%x)=%q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestFuzzyFindLog(t *testing.T) {
	var tests = []struct {
		name, in string
		want     []string
	}{
		{
			name: "NotFound",
			in:   "aabbcc",
			want: []string{},
		},
		{
			name: "FoundByKey64",
			in:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByKeyHex",
			in:   "3059301306072a8648ce3d020106082a8648ce3d03010703420004205b18c83cc18bb3310800bfa090572bb7478c6fb568b08e9078e9a073ea4f28212e9cc0f4161baaf9d5d7a980c34e2f523c9801254624252823772d05c2407a",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByKeyHashHex",
			in:   " ee 4b bd b7 75 ce 60 ba e1 42 69 1f ab e1 9e 66 a3 0f 7e 5f b0 72 d8 83 00 c4 7b 89 7a a8 fd cb",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByKeyHashHexPrefix",
			in:   "ee4bbdb7",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByKeyHash64",
			in:   "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByName",
			in:   "Rocketeer",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByNameDifferentCase",
			in:   "rocketeer",
			want: []string{"Google 'Rocketeer' log"},
		},
		{
			name: "FoundByURL",
			in:   "https://ct.googleapis.com/rocketeer",
			want: []string{"Google 'Rocketeer' log"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := sampleLogList.FuzzyFindLog(test.in)
			got := make([]string, len(logs))
			for i, l := range logs {
				got[i] = l.Description
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("FuzzyFindLog(%q)=%v, want %v", test.in, got, test.want)
			}
		})
	}
}

func TestStripInternalSpace(t *testing.T) {
	var tests = []struct {
		in   string
		want string
	}{
		{in: "xyz", want: "xyz"},
		{in: "x y z", want: "xyz"},
		{in: "x  yz  ", want: "xyz"},
		{in: " xyz ", want: "xyz"},
		{in: "xy\t\tz", want: "xyz"},
	}

	for _, test := range tests {
		got := stripInternalSpace(test.in)
		if got != test.want {
			t.Errorf("stripInternalSpace(%q)=%q, want %q", test.in, got, test.want)
		}
	}
}

func TestLogStatesString(t *testing.T) {
	var tests = []struct {
		name   string
		logURL string
		want   string
	}{
		{name: "ReadOnly", logURL: "https://ct.googleapis.com/aviator/", want: "ReadOnlyLogStatus"},
		{name: "Empty", logURL: "https://ct.googleapis.com/racketeer/", want: "UndefinedLogStatus"},
		{name: "Usable", logURL: "https://ct.googleapis.com/icarus/", want: "UsableLogStatus"},
		{name: "Retired", logURL: "https://log.bob.io", want: "RetiredLogStatus"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := sampleLogList.FindLogByURL(test.logURL)
			if got := l.State.String(); got != test.want {
				t.Errorf("%q:  Log.State.String() = %s, want %s", test.logURL, got, test.want)
			}
		})
	}
}

func TestLogStatesActive(t *testing.T) {
	a := &LogState{Timestamp: time.Unix(1460678400, 0).UTC()}
	f := &ReadOnlyLogState{
		LogState: LogState{Timestamp: time.Unix(1480512258, 330000000).UTC()},
		FinalTreeHead: TreeHead{
			TreeSize:       46466472,
			SHA256RootHash: []byte{},
		},
	}
	var tests = []struct {
		name       string
		in         *LogStates
		wantState  *LogState
		wantFState *ReadOnlyLogState
	}{
		{
			name: "Retired",
			in: &LogStates{
				Retired: a,
			},
			wantState:  a,
			wantFState: nil,
		},
		{
			name: "ReadOnly",
			in: &LogStates{
				ReadOnly: f,
			},
			wantState:  nil,
			wantFState: f,
		},
		{
			name: "Qualified",
			in: &LogStates{
				Qualified: a,
			},
			wantState:  a,
			wantFState: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotState, gotFState := test.in.Active()
			if gotState != test.wantState {
				t.Errorf("Log-state from Active() = %q, want %q", gotState, test.wantState)
			}
			if gotFState != test.wantFState {
				t.Errorf("ReadOnly Log-state from Active() = %q, want %q", gotFState, test.wantFState)
			}
		})
	}
}

func changeOperatorEmail(op Operator, email string) Operator {
	op.Email = make([]string, 1)
	op.Email[0] = email
	return op
}

func TestGoogleOperated(t *testing.T) {
	var tests = []struct {
		in  Operator
		out bool
	}{
		{in: *(sampleLogList.Operators[0]), out: true},
		{in: *sampleLogList.Operators[1], out: false},
		{in: changeOperatorEmail(*sampleLogList.Operators[1], "google-ct-logs@googlegroups"), out: true},
		{in: changeOperatorEmail(*sampleLogList.Operators[0], "operator@googlegroups"), out: false},
	}
	for _, test := range tests {
		isGoog := test.in.GoogleOperated()
		if isGoog != test.out {
			t.Errorf("GoogleOperated status for %s is %t, want %t", test.in.Name, isGoog, test.out)
		}
	}
}

func deb64(b string) []byte {
	data, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		panic(fmt.Sprintf("hard-coded test data failed to decode: %v", err))
	}
	return data
}
