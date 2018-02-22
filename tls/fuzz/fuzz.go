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

// Package fuzz holds a fuzz driver for the tls library.
package fuzz

import "github.com/google/certificate-transparency-go/tls"

// Structures for TLS serialization that attempt to exercise all
// possible options

// Outer holds different possibilities.
type Outer struct {
	Sel          tls.Enum     `tls:"maxval:3"`
	OneOfEach    *OneOfEach   `tls:"selector:Sel,val:0"`
	ChoosyThing  *VariantItem `tls:"selector:Sel,val:1"`
	AnotherThing *Something   `tls:"selector:Sel,val:2"`
}

// OneOfEach has each fixed length type.
type OneOfEach struct {
	Val8   uint8
	Val16  uint16
	Val24  tls.Uint24
	Val32  uint32
	Val64  uint64
	Choice tls.Enum `tls:"size:3"`
	Buffer [12]byte
}

// VariantItem has a choice.
type VariantItem struct {
	Sel    tls.Enum `tls:"maxval:2"`
	Data16 *uint16  `tls:"selector:Sel,val:1"`
	Data32 *uint32  `tls:"selector:Sel,val:2"`
}

// InnerType holds a variable length opaque field.
type InnerType struct {
	Val []byte `tls:"minlen:1,maxlen:65535"`
}

// Something has a variable length slice of variable length data.
type Something struct {
	Inners []InnerType `tls:"minlen:1,maxlen:65535"`
}

// Fuzz is a go-fuzz (https://github.com/dvyukov/go-fuzz) entrypoint
// for fuzzing the parsing of TLS-encoded data.
func Fuzz(data []byte) int {
	var result Outer
	if _, err := tls.Unmarshal(data, &result); err != nil {
		return 0
	}
	return 1 // Lexically correct
}
