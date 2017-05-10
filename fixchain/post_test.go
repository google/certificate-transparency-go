// Copyright 2016 Google Inc. All Rights Reserved.
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

package fixchain

import (
	"net/http"
	"testing"
)

func TestPostChainToLog(t *testing.T) {
	for i, test := range postTests {
		client := &http.Client{Transport: &postTestRoundTripper{t: t, test: &test, testIndex: i}}
		ferr := PostChainToLog(extractTestChain(t, i, test.chain), client, test.url)

		if ferr == nil {
			if test.ferr.Type != None {
				t.Errorf("#%d: PostChainToLog() didn't return FixError, expected FixError of type %s", i, test.ferr.TypeString())
			}
		} else {
			if ferr.Type != test.ferr.Type {
				t.Errorf("#%d: PostChainToLog() returned FixError of type %s, expected %s", i, ferr.TypeString(), test.ferr.TypeString())
			}
		}
	}
}
