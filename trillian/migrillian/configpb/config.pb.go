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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.12.4
// source: migrillian/configpb/config.proto

package configpb

import (
	configpb "github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	keyspb "github.com/google/trillian/crypto/keyspb"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// IdentityFunction specifies how Trillian identity hash is computed.
type IdentityFunction int32

const (
	IdentityFunction_UNKNOWN_IDENTITY_FUNCTION IdentityFunction = 0
	// Returns SHA256 hash of the certificate DER. This is the same function that
	// CTFE uses when submitting add-[pre-]chain entries to Trillian.
	//
	// For example, it can be used when migrating a CT log to Trillian. Using the
	// same function as CTFE makes any newly submitted entries compatible with the
	// ones that migrated from the source log.
	IdentityFunction_SHA256_CERT_DATA IdentityFunction = 1
	// Returns SHA256 hash of the leaf index.
	//
	// For example, this function can be used for mirroring CT logs. Since the
	// source logs might have duplicates of different kinds (depends on the
	// operator), this function allows storing them all (unlike SHA256_CERT_DATA).
	// Note that the CTFE log must stay read-only (mirror), as CTFE's identity
	// hash is incompatible.
	IdentityFunction_SHA256_LEAF_INDEX IdentityFunction = 2
)

// Enum value maps for IdentityFunction.
var (
	IdentityFunction_name = map[int32]string{
		0: "UNKNOWN_IDENTITY_FUNCTION",
		1: "SHA256_CERT_DATA",
		2: "SHA256_LEAF_INDEX",
	}
	IdentityFunction_value = map[string]int32{
		"UNKNOWN_IDENTITY_FUNCTION": 0,
		"SHA256_CERT_DATA":          1,
		"SHA256_LEAF_INDEX":         2,
	}
)

func (x IdentityFunction) Enum() *IdentityFunction {
	p := new(IdentityFunction)
	*p = x
	return p
}

func (x IdentityFunction) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IdentityFunction) Descriptor() protoreflect.EnumDescriptor {
	return file_migrillian_configpb_config_proto_enumTypes[0].Descriptor()
}

func (IdentityFunction) Type() protoreflect.EnumType {
	return &file_migrillian_configpb_config_proto_enumTypes[0]
}

func (x IdentityFunction) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IdentityFunction.Descriptor instead.
func (IdentityFunction) EnumDescriptor() ([]byte, []int) {
	return file_migrillian_configpb_config_proto_rawDescGZIP(), []int{0}
}

// MigrationConfig describes the configuration options for a single CT log
// migration instance.
type MigrationConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The URI of the source CT log, e.g. "https://ct.googleapis.com/pilot".
	SourceUri string `protobuf:"bytes,1,opt,name=source_uri,json=sourceUri,proto3" json:"source_uri,omitempty"`
	// The public key of the source log.
	PublicKey *keyspb.PublicKey `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// The name of the backend which this log migrates to. The name must be one of
	// those defined in the LogBackendSet.
	//
	// Deprecated. TODO(pavelkalinnikov): Remove it.
	//
	// Deprecated: Do not use.
	LogBackendName string `protobuf:"bytes,3,opt,name=log_backend_name,json=logBackendName,proto3" json:"log_backend_name,omitempty"`
	// The ID of a Trillian PREORDERED_LOG tree that stores the log data.
	LogId int64 `protobuf:"varint,4,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"`
	// Max number of entries per get-entries request from the source log.
	BatchSize int32 `protobuf:"varint,5,opt,name=batch_size,json=batchSize,proto3" json:"batch_size,omitempty"`
	// Determines whether the migration should run continuously, i.e. watch and
	// follow the updates of the source log's STH. For example, this mode can be
	// used to support a mirror CT log.
	IsContinuous bool `protobuf:"varint,6,opt,name=is_continuous,json=isContinuous,proto3" json:"is_continuous,omitempty"`
	// The log entry index to start fetching at. If negative, then it is assumed
	// equal to the current Trillian tree size.
	// Ignored in continuous mode which starts at the point where it stopped (e.g.
	// the current Trillian tree size in a simple case).
	StartIndex int64 `protobuf:"varint,7,opt,name=start_index,json=startIndex,proto3" json:"start_index,omitempty"`
	// The log index to end fetching at, non-inclusive. If zero, fetch up to the
	// source log's current STH. Ignored in continuous mode which keeps updating
	// STH and fetching up to that.
	EndIndex int64 `protobuf:"varint,8,opt,name=end_index,json=endIndex,proto3" json:"end_index,omitempty"`
	// The number of parallel get-entries fetchers. Assumed equal to 1 if not
	// specified.
	NumFetchers int32 `protobuf:"varint,9,opt,name=num_fetchers,json=numFetchers,proto3" json:"num_fetchers,omitempty"`
	// The number of parallel workers submitting entries to Trillian. Assumed
	// equal to 1 if not specified.
	NumSubmitters int32 `protobuf:"varint,10,opt,name=num_submitters,json=numSubmitters,proto3" json:"num_submitters,omitempty"`
	// Max number of batches in fetchers->submitters channel.
	ChannelSize int32 `protobuf:"varint,11,opt,name=channel_size,json=channelSize,proto3" json:"channel_size,omitempty"`
	// The function that computes LeafIdentityHash for Trillian log entries.
	IdentityFunction IdentityFunction `protobuf:"varint,12,opt,name=identity_function,json=identityFunction,proto3,enum=configpb.IdentityFunction" json:"identity_function,omitempty"`
	// If set to false (by default), then Migrillian verifies that the tree as
	// seen by Trillian is consistent with the current STH of the source CT log.
	// It invokes the get-sth-consistency endpoint (section 4.4 of RFC 6962) with
	// the corresponding tree sizes, and verifies the returned proof.
	NoConsistencyCheck bool `protobuf:"varint,13,opt,name=no_consistency_check,json=noConsistencyCheck,proto3" json:"no_consistency_check,omitempty"`
}

func (x *MigrationConfig) Reset() {
	*x = MigrationConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_migrillian_configpb_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MigrationConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MigrationConfig) ProtoMessage() {}

func (x *MigrationConfig) ProtoReflect() protoreflect.Message {
	mi := &file_migrillian_configpb_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MigrationConfig.ProtoReflect.Descriptor instead.
func (*MigrationConfig) Descriptor() ([]byte, []int) {
	return file_migrillian_configpb_config_proto_rawDescGZIP(), []int{0}
}

func (x *MigrationConfig) GetSourceUri() string {
	if x != nil {
		return x.SourceUri
	}
	return ""
}

func (x *MigrationConfig) GetPublicKey() *keyspb.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// Deprecated: Do not use.
func (x *MigrationConfig) GetLogBackendName() string {
	if x != nil {
		return x.LogBackendName
	}
	return ""
}

func (x *MigrationConfig) GetLogId() int64 {
	if x != nil {
		return x.LogId
	}
	return 0
}

func (x *MigrationConfig) GetBatchSize() int32 {
	if x != nil {
		return x.BatchSize
	}
	return 0
}

func (x *MigrationConfig) GetIsContinuous() bool {
	if x != nil {
		return x.IsContinuous
	}
	return false
}

func (x *MigrationConfig) GetStartIndex() int64 {
	if x != nil {
		return x.StartIndex
	}
	return 0
}

func (x *MigrationConfig) GetEndIndex() int64 {
	if x != nil {
		return x.EndIndex
	}
	return 0
}

func (x *MigrationConfig) GetNumFetchers() int32 {
	if x != nil {
		return x.NumFetchers
	}
	return 0
}

func (x *MigrationConfig) GetNumSubmitters() int32 {
	if x != nil {
		return x.NumSubmitters
	}
	return 0
}

func (x *MigrationConfig) GetChannelSize() int32 {
	if x != nil {
		return x.ChannelSize
	}
	return 0
}

func (x *MigrationConfig) GetIdentityFunction() IdentityFunction {
	if x != nil {
		return x.IdentityFunction
	}
	return IdentityFunction_UNKNOWN_IDENTITY_FUNCTION
}

func (x *MigrationConfig) GetNoConsistencyCheck() bool {
	if x != nil {
		return x.NoConsistencyCheck
	}
	return false
}

// MigrationConfigSet is a set of MigrationConfig messages.
type MigrationConfigSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Config []*MigrationConfig `protobuf:"bytes,1,rep,name=config,proto3" json:"config,omitempty"`
}

func (x *MigrationConfigSet) Reset() {
	*x = MigrationConfigSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_migrillian_configpb_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MigrationConfigSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MigrationConfigSet) ProtoMessage() {}

func (x *MigrationConfigSet) ProtoReflect() protoreflect.Message {
	mi := &file_migrillian_configpb_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MigrationConfigSet.ProtoReflect.Descriptor instead.
func (*MigrationConfigSet) Descriptor() ([]byte, []int) {
	return file_migrillian_configpb_config_proto_rawDescGZIP(), []int{1}
}

func (x *MigrationConfigSet) GetConfig() []*MigrationConfig {
	if x != nil {
		return x.Config
	}
	return nil
}

// MigrillianConfig holds configuration for multiple migration / mirroring jobs.
type MigrillianConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The set of backends that this configuration will use to send requests to.
	// The names of the backends in the LogBackendSet must all be distinct.
	//
	// Deprecated. TODO(pavelkalinnikov): Remove it.
	//
	// Deprecated: Do not use.
	Backends *configpb.LogBackendSet `protobuf:"bytes,1,opt,name=backends,proto3" json:"backends,omitempty"`
	// The set of migrations that will use the above backends. All the protos in
	// it must set a valid log_backend_name for the config to be usable.
	MigrationConfigs *MigrationConfigSet `protobuf:"bytes,2,opt,name=migration_configs,json=migrationConfigs,proto3" json:"migration_configs,omitempty"`
}

func (x *MigrillianConfig) Reset() {
	*x = MigrillianConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_migrillian_configpb_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MigrillianConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MigrillianConfig) ProtoMessage() {}

func (x *MigrillianConfig) ProtoReflect() protoreflect.Message {
	mi := &file_migrillian_configpb_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MigrillianConfig.ProtoReflect.Descriptor instead.
func (*MigrillianConfig) Descriptor() ([]byte, []int) {
	return file_migrillian_configpb_config_proto_rawDescGZIP(), []int{2}
}

// Deprecated: Do not use.
func (x *MigrillianConfig) GetBackends() *configpb.LogBackendSet {
	if x != nil {
		return x.Backends
	}
	return nil
}

func (x *MigrillianConfig) GetMigrationConfigs() *MigrationConfigSet {
	if x != nil {
		return x.MigrationConfigs
	}
	return nil
}

var File_migrillian_configpb_config_proto protoreflect.FileDescriptor

var file_migrillian_configpb_config_proto_rawDesc = []byte{
	0x0a, 0x20, 0x6d, 0x69, 0x67, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x70, 0x62, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x08, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x1a, 0x23, 0x74, 0x72,
	0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x63, 0x74, 0x66, 0x65, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x70, 0x62, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1a, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x6b, 0x65, 0x79, 0x73, 0x70, 0x62,
	0x2f, 0x6b, 0x65, 0x79, 0x73, 0x70, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x91, 0x04,
	0x0a, 0x0f, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x75, 0x72, 0x69, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x55, 0x72, 0x69,
	0x12, 0x30, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x6b, 0x65, 0x79, 0x73, 0x70, 0x62, 0x2e, 0x50, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x12, 0x2c, 0x0a, 0x10, 0x6c, 0x6f, 0x67, 0x5f, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e,
	0x64, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01,
	0x52, 0x0e, 0x6c, 0x6f, 0x67, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x15, 0x0a, 0x06, 0x6c, 0x6f, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x05, 0x6c, 0x6f, 0x67, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x61, 0x74, 0x63, 0x68,
	0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x62, 0x61, 0x74,
	0x63, 0x68, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x63, 0x6f, 0x6e,
	0x74, 0x69, 0x6e, 0x75, 0x6f, 0x75, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x69,
	0x73, 0x43, 0x6f, 0x6e, 0x74, 0x69, 0x6e, 0x75, 0x6f, 0x75, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1b, 0x0a, 0x09,
	0x65, 0x6e, 0x64, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x08, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x08, 0x65, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x21, 0x0a, 0x0c, 0x6e, 0x75, 0x6d,
	0x5f, 0x66, 0x65, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x0b, 0x6e, 0x75, 0x6d, 0x46, 0x65, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x12, 0x25, 0x0a, 0x0e,
	0x6e, 0x75, 0x6d, 0x5f, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x72, 0x73, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0d, 0x6e, 0x75, 0x6d, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x74,
	0x65, 0x72, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x73,
	0x69, 0x7a, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x63, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x47, 0x0a, 0x11, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x49, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x10, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x30, 0x0a, 0x14, 0x6e, 0x6f, 0x5f, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63,
	0x79, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x08, 0x52, 0x12, 0x6e,
	0x6f, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x43, 0x68, 0x65, 0x63,
	0x6b, 0x22, 0x47, 0x0a, 0x12, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x53, 0x65, 0x74, 0x12, 0x31, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x70, 0x62, 0x2e, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x96, 0x01, 0x0a, 0x10, 0x4d,
	0x69, 0x67, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12,
	0x37, 0x0a, 0x08, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x4c, 0x6f, 0x67,
	0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x74, 0x42, 0x02, 0x18, 0x01, 0x52, 0x08,
	0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x73, 0x12, 0x49, 0x0a, 0x11, 0x6d, 0x69, 0x67, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x4d,
	0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x65,
	0x74, 0x52, 0x10, 0x6d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x73, 0x2a, 0x5e, 0x0a, 0x10, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x46,
	0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x19, 0x55, 0x4e, 0x4b, 0x4e, 0x4f,
	0x57, 0x4e, 0x5f, 0x49, 0x44, 0x45, 0x4e, 0x54, 0x49, 0x54, 0x59, 0x5f, 0x46, 0x55, 0x4e, 0x43,
	0x54, 0x49, 0x4f, 0x4e, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36,
	0x5f, 0x43, 0x45, 0x52, 0x54, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11,
	0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x5f, 0x4c, 0x45, 0x41, 0x46, 0x5f, 0x49, 0x4e, 0x44, 0x45,
	0x58, 0x10, 0x02, 0x42, 0x4c, 0x5a, 0x4a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x63,
	0x79, 0x2d, 0x67, 0x6f, 0x2f, 0x74, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x6d, 0x69,
	0x67, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70,
	0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_migrillian_configpb_config_proto_rawDescOnce sync.Once
	file_migrillian_configpb_config_proto_rawDescData = file_migrillian_configpb_config_proto_rawDesc
)

func file_migrillian_configpb_config_proto_rawDescGZIP() []byte {
	file_migrillian_configpb_config_proto_rawDescOnce.Do(func() {
		file_migrillian_configpb_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_migrillian_configpb_config_proto_rawDescData)
	})
	return file_migrillian_configpb_config_proto_rawDescData
}

var file_migrillian_configpb_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_migrillian_configpb_config_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_migrillian_configpb_config_proto_goTypes = []interface{}{
	(IdentityFunction)(0),          // 0: configpb.IdentityFunction
	(*MigrationConfig)(nil),        // 1: configpb.MigrationConfig
	(*MigrationConfigSet)(nil),     // 2: configpb.MigrationConfigSet
	(*MigrillianConfig)(nil),       // 3: configpb.MigrillianConfig
	(*keyspb.PublicKey)(nil),       // 4: keyspb.PublicKey
	(*configpb.LogBackendSet)(nil), // 5: configpb.LogBackendSet
}
var file_migrillian_configpb_config_proto_depIdxs = []int32{
	4, // 0: configpb.MigrationConfig.public_key:type_name -> keyspb.PublicKey
	0, // 1: configpb.MigrationConfig.identity_function:type_name -> configpb.IdentityFunction
	1, // 2: configpb.MigrationConfigSet.config:type_name -> configpb.MigrationConfig
	5, // 3: configpb.MigrillianConfig.backends:type_name -> configpb.LogBackendSet
	2, // 4: configpb.MigrillianConfig.migration_configs:type_name -> configpb.MigrationConfigSet
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_migrillian_configpb_config_proto_init() }
func file_migrillian_configpb_config_proto_init() {
	if File_migrillian_configpb_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_migrillian_configpb_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MigrationConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_migrillian_configpb_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MigrationConfigSet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_migrillian_configpb_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MigrillianConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_migrillian_configpb_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_migrillian_configpb_config_proto_goTypes,
		DependencyIndexes: file_migrillian_configpb_config_proto_depIdxs,
		EnumInfos:         file_migrillian_configpb_config_proto_enumTypes,
		MessageInfos:      file_migrillian_configpb_config_proto_msgTypes,
	}.Build()
	File_migrillian_configpb_config_proto = out.File
	file_migrillian_configpb_config_proto_rawDesc = nil
	file_migrillian_configpb_config_proto_goTypes = nil
	file_migrillian_configpb_config_proto_depIdxs = nil
}
