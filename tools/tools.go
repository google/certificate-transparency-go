// Copyright 2016 Google LLC. All Rights Reserved.
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

//go:build tools
// +build tools

// Package tools tracks dependencies on binaries not otherwise referenced in this codebase.
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	_ "github.com/fullstorydev/grpcurl/cmd/grpcurl"
	_ "github.com/golang/mock/mockgen"
	_ "github.com/google/trillian/cmd/createtree"
	_ "go.etcd.io/etcd/etcdctl/v3"
	_ "go.etcd.io/etcd/v3"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "google.golang.org/protobuf/proto"
)
