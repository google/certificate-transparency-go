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

package loglist

import (
	"encoding/base64"
	"fmt"
)

var SampleLogList = LogList{
	Operators: []Operator{
		{ID: 0, Name: "Google"},
		{ID: 1, Name: "Bob's CT Log Shop"},
	},
	Logs: []Log{
		{
			Description:       "Google 'Aviator' log",
			Key:               deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q=="),
			URL:               "ct.googleapis.com/aviator/",
			MaximumMergeDelay: 86400,
			OperatedBy:        []int{0},
			FinalSTH: &STH{
				TreeSize:          46466472,
				Timestamp:         1480512258330,
				SHA256RootHash:    deb64("LcGcZRsm+LGYmrlyC5LXhV1T6OD8iH5dNlb0sEJl9bA="),
				TreeHeadSignature: deb64("BAMASDBGAiEA/M0Nvt77aNe+9eYbKsv6rRpTzFTKa5CGqb56ea4hnt8CIQCJDE7pL6xgAewMd5i3G1lrBWgFooT2kd3+zliEz5Rw8w=="),
			},
			DNSAPIEndpoint: "aviator.ct.googleapis.com",
		},
		{
			Description:       "Google 'Icarus' log",
			Key:               deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA=="),
			URL:               "ct.googleapis.com/icarus/",
			MaximumMergeDelay: 86400,
			OperatedBy:        []int{0},
			DNSAPIEndpoint:    "icarus.ct.googleapis.com",
		},
		{
			Description:       "Google 'Rocketeer' log",
			Key:               deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
			URL:               "ct.googleapis.com/rocketeer/",
			MaximumMergeDelay: 86400,
			OperatedBy:        []int{0},
			DNSAPIEndpoint:    "rocketeer.ct.googleapis.com",
		},
		{
			Description: "Google 'Racketeer' log",
			// Key value chosed to have a hash that starts ee4... (specifically ee412fe25948348961e2f3e08c682e813ec0ff770b6d75171763af3014ff9768)
			Key:               deb64("Hy2TPTZ2yq9ASMmMZiB9SZEUx5WNH5G0Ft5Tm9vKMcPXA+ic/Ap3gg6fXzBJR8zLkt5lQjvKMdbHYMGv7yrsZg=="),
			URL:               "ct.googleapis.com/racketeer/",
			MaximumMergeDelay: 86400,
			OperatedBy:        []int{0},
			DNSAPIEndpoint:    "racketeer.ct.googleapis.com",
		},
		{
			Description:       "Bob's Dubious Log",
			Key:               deb64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA=="),
			URL:               "log.bob.io",
			MaximumMergeDelay: 86400,
			OperatedBy:        []int{1},

			DisqualifiedAt: 1460678400,
			DNSAPIEndpoint: "dubious-bob.ct.googleapis.com",
		},
	},
}

func deb64(b string) []byte {
	data, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		panic(fmt.Sprintf("hard-coded test data failed to decode: %v", err))
	}
	return data
}

