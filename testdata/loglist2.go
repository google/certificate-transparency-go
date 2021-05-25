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

package testdata

var (
	// SampleLogList2 is used for testing.
	SampleLogList2 = `{"operators":[` +
		`{"name":"Google",` +
		`"email":["google-ct-logs@googlegroups.com"],` +
		`"logs":[` +
		`{"description":"Google 'Aviator' log",` +
		`"log_id":"aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",` +
		`"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==",` +
		`"url":"https://ct.googleapis.com/aviator/",` +
		`"dns":"aviator.ct.googleapis.com",` +
		`"mmd":86400,` +
		`"state":{"readonly":` +
		`{"timestamp":"2016-11-30T13:24:18.33Z",` +
		`"final_tree_head":{"sha256_root_hash":"LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA=","tree_size":46466472}}` +
		`},` +
		`"temporal_interval":{"start_inclusive":"2014-03-07T11:06:00Z","end_exclusive":"2015-03-07T12:00:00Z"}` +
		`},` +
		`{"description":"Google 'Icarus' log",` +
		`"log_id":"KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=",` +
		`"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",` +
		`"url":"https://ct.googleapis.com/icarus/","dns":"icarus.ct.googleapis.com",` +
		`"mmd":86400,` +
		`"state":{"usable":{"timestamp":"2018-02-27T00:00:00Z"}}` +
		`},` +
		`{"description":"Google 'Racketeer' log",` +
		`"log_id":"7kEv4llINIlh4vPgjGgugT7A/3cLbXUXF2OvMBT/l2g=",` +
		`"key":"Hy2TPTZ2yq9ASMmMZiB9SZEUx5WNH5G0Ft5Tm9vKMcPXA+ic/Ap3gg6fXzBJR8zLkt5lQjvKMdbHYMGv7yrsZg==",` +
		`"url":"https://ct.googleapis.com/racketeer/",` +
		`"dns":"racketeer.ct.googleapis.com",` +
		`"mmd":86400` +
		`},` +
		`{"description":"Google 'Rocketeer' log",` +
		`"log_id":"7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",` +
		`"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",` +
		`"url":"https://ct.googleapis.com/rocketeer/",` +
		`"dns":"rocketeer.ct.googleapis.com",` +
		`"state":{"usable":{"timestamp":"2018-02-27T00:00:00Z"}},` +
		`"mmd":86400` +
		`},` +
		`{"description":"Google 'Argon2020' log",` +
		`"log_id": "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=",` +
		`"key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==",` +
		`"url":"https://ct.googleapis.com/logs/argon2020/",` +
		`"dns":"argon2020.ct.googleapis.com",` +
		`"mmd":86400,` +
		`"state":{"qualified":{"timestamp":"2018-02-27T00:00:00Z"}},` +
		`"temporal_interval":{"start_inclusive":"2020-01-01T00:00:00Z","end_exclusive":"2021-01-01T00:00:00Z"}` +
		`}` +
		`]},` +
		`{"name":"Bob's CT Log Shop",` +
		`"email":["bob@example.com"],` +
		`"logs":[` +
		`{"description":"Bob's Dubious Log",` +
		`"log_id":"zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=",` +
		`"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==",` +
		`"url":"https://log.bob.io",` +
		`"dns":"dubious-bob.ct.googleapis.com",` +
		`"mmd":86400,` +
		`"state":{"retired":{"timestamp":"2016-04-15T00:00:00Z"}},` +
		`"temporal_interval":{"start_inclusive":"2014-11-07T12:00:00Z","end_exclusive":"2015-03-07T12:00:00Z"}}` +
		`]}]}`
)
