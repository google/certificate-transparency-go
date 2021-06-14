// Copyright 2017 Google LLC. All Rights Reserved.
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
// source: trillian/ctfe/configpb/config.proto

package configpb

import (
	any "github.com/golang/protobuf/ptypes/any"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
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

type LogBackend struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name defines the name of the log backend for use in LogConfig messages and must be unique.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// backend_spec defines the RPC endpoint that clients should use to send requests
	// to this log backend. These should be in the same format as rpcBackendFlag in the
	// CTFE main and must not be an empty string.
	BackendSpec string `protobuf:"bytes,2,opt,name=backend_spec,json=backendSpec,proto3" json:"backend_spec,omitempty"`
}

func (x *LogBackend) Reset() {
	*x = LogBackend{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogBackend) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogBackend) ProtoMessage() {}

func (x *LogBackend) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogBackend.ProtoReflect.Descriptor instead.
func (*LogBackend) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{0}
}

func (x *LogBackend) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *LogBackend) GetBackendSpec() string {
	if x != nil {
		return x.BackendSpec
	}
	return ""
}

// LogBackendSet supports a configuration where a single set of frontends handle
// requests for multiple backends. For example this could be used to run different
// backends in different geographic regions.
type LogBackendSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Backend []*LogBackend `protobuf:"bytes,1,rep,name=backend,proto3" json:"backend,omitempty"`
}

func (x *LogBackendSet) Reset() {
	*x = LogBackendSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogBackendSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogBackendSet) ProtoMessage() {}

func (x *LogBackendSet) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogBackendSet.ProtoReflect.Descriptor instead.
func (*LogBackendSet) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{1}
}

func (x *LogBackendSet) GetBackend() []*LogBackend {
	if x != nil {
		return x.Backend
	}
	return nil
}

// LogConfigSet is a set of LogConfig messages.
type LogConfigSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Config []*LogConfig `protobuf:"bytes,1,rep,name=config,proto3" json:"config,omitempty"`
}

func (x *LogConfigSet) Reset() {
	*x = LogConfigSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogConfigSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogConfigSet) ProtoMessage() {}

func (x *LogConfigSet) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogConfigSet.ProtoReflect.Descriptor instead.
func (*LogConfigSet) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{2}
}

func (x *LogConfigSet) GetConfig() []*LogConfig {
	if x != nil {
		return x.Config
	}
	return nil
}

// LogConfig describes the configuration options for a log instance.
//
// NEXT_ID: 19
type LogConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of a Trillian tree that stores the log data. The tree type must be
	// LOG for regular CT logs. For mirror logs it must be either PREORDERED_LOG
	// or LOG, and can change at runtime. CTFE in mirror mode uses only read API
	// which is common for both types.
	LogId int64 `protobuf:"varint,1,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"`
	// prefix is the name of the log. It will come after the global or
	// override handler prefix. For example if the handler prefix is "/logs"
	// and prefix is "vogon" the get-sth handler for this log will be
	// available at "/logs/vogon/ct/v1/get-sth". The prefix cannot be empty
	// and must not include "/" path separator characters.
	Prefix string `protobuf:"bytes,2,opt,name=prefix,proto3" json:"prefix,omitempty"`
	// override_handler_prefix if set to a non empty value overrides the global
	// handler prefix for an individual log. For example this field is set to
	// "/otherlogs" then a log with prefix "vogon" will make it's get-sth handler
	// available at "/otherlogs/vogon/ct/v1/get-sth" regardless of what the
	// global prefix is. Can be set to '/' to make the get-sth handler register
	// at "/vogon/ct/v1/get-sth".
	OverrideHandlerPrefix string `protobuf:"bytes,13,opt,name=override_handler_prefix,json=overrideHandlerPrefix,proto3" json:"override_handler_prefix,omitempty"`
	// Paths to the files containing root certificates that are acceptable to the
	// log. The certs are served through get-roots endpoint. Optional in mirrors.
	RootsPemFile []string `protobuf:"bytes,3,rep,name=roots_pem_file,json=rootsPemFile,proto3" json:"roots_pem_file,omitempty"`
	// The private key used for signing STHs etc. Not required for mirrors.
	PrivateKey *any.Any `protobuf:"bytes,4,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// The public key matching the above private key (if both are present). It is
	// used only by mirror logs for verifying the source log's signatures, but can
	// be specified for regular logs as well for the convenience of test tools.
	PublicKey *keyspb.PublicKey `protobuf:"bytes,5,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// If reject_expired is true then the certificate validity period will be
	// checked against the current time during the validation of submissions.
	// This will cause expired certificates to be rejected.
	RejectExpired bool `protobuf:"varint,6,opt,name=reject_expired,json=rejectExpired,proto3" json:"reject_expired,omitempty"`
	// If reject_unexpired is true then CTFE rejects certificates that are either
	// currently valid or not yet valid.
	RejectUnexpired bool `protobuf:"varint,17,opt,name=reject_unexpired,json=rejectUnexpired,proto3" json:"reject_unexpired,omitempty"`
	// If set, ext_key_usages will restrict the set of such usages that the
	// server will accept. By default all are accepted. The values specified
	// must be ones known to the x509 package.
	ExtKeyUsages []string `protobuf:"bytes,7,rep,name=ext_key_usages,json=extKeyUsages,proto3" json:"ext_key_usages,omitempty"`
	// not_after_start defines the start of the range of acceptable NotAfter
	// values, inclusive.
	// Leaving this unset implies no lower bound to the range.
	NotAfterStart *timestamp.Timestamp `protobuf:"bytes,8,opt,name=not_after_start,json=notAfterStart,proto3" json:"not_after_start,omitempty"`
	// not_after_limit defines the end of the range of acceptable NotAfter values,
	// exclusive.
	// Leaving this unset implies no upper bound to the range.
	NotAfterLimit *timestamp.Timestamp `protobuf:"bytes,9,opt,name=not_after_limit,json=notAfterLimit,proto3" json:"not_after_limit,omitempty"`
	// accept_only_ca controls whether or not *only* certificates with the CA bit
	// set will be accepted.
	AcceptOnlyCa bool `protobuf:"varint,10,opt,name=accept_only_ca,json=acceptOnlyCa,proto3" json:"accept_only_ca,omitempty"`
	// backend_name if set indicates which backend serves this log. The name must be
	// one of those defined in the LogBackendSet.
	LogBackendName string `protobuf:"bytes,11,opt,name=log_backend_name,json=logBackendName,proto3" json:"log_backend_name,omitempty"`
	// If set, the log is a mirror, i.e. it serves the data of another (source)
	// log. It doesn't handle write requests (add-chain, etc.), so it's not a
	// fully fledged RFC-6962 log, but the tree read requests like get-entries and
	// get-consistency-proof are compatible. A mirror doesn't have the source
	// log's key and can't sign STHs. Consequently, the log operator must ensure
	// to channel source log's STHs into CTFE.
	IsMirror bool `protobuf:"varint,12,opt,name=is_mirror,json=isMirror,proto3" json:"is_mirror,omitempty"`
	// The Maximum Merge Delay (MMD) of this log in seconds. See RFC6962 section 3
	// for definition of MMD. If zero, the log does not provide an MMD guarantee
	// (for example, it is a frozen log).
	MaxMergeDelaySec int32 `protobuf:"varint,14,opt,name=max_merge_delay_sec,json=maxMergeDelaySec,proto3" json:"max_merge_delay_sec,omitempty"`
	// The merge delay that the underlying log implementation is able/targeting to
	// provide. This option is exposed in CTFE metrics, and can be particularly
	// useful to catch when the log is behind but has not yet violated the strict
	// MMD limit.
	// Log operator should decide what exactly EMD means for them. For example, it
	// can be a 99-th percentile of merge delays that they observe, and they can
	// alert on the actual merge delay going above a certain multiple of this EMD.
	ExpectedMergeDelaySec int32 `protobuf:"varint,15,opt,name=expected_merge_delay_sec,json=expectedMergeDelaySec,proto3" json:"expected_merge_delay_sec,omitempty"`
	// The STH that this log will serve permanently (if present). Frozen STH must
	// be signed by this log's private key, and will be verified using the public
	// key specified in this config.
	FrozenSth *SignedTreeHead `protobuf:"bytes,16,opt,name=frozen_sth,json=frozenSth,proto3" json:"frozen_sth,omitempty"`
	// A list of X.509 extension OIDs, in dotted string form (e.g. "2.3.4.5")
	// which should cause submissions to be rejected.
	RejectExtensions []string `protobuf:"bytes,18,rep,name=reject_extensions,json=rejectExtensions,proto3" json:"reject_extensions,omitempty"`
}

func (x *LogConfig) Reset() {
	*x = LogConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogConfig) ProtoMessage() {}

func (x *LogConfig) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogConfig.ProtoReflect.Descriptor instead.
func (*LogConfig) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{3}
}

func (x *LogConfig) GetLogId() int64 {
	if x != nil {
		return x.LogId
	}
	return 0
}

func (x *LogConfig) GetPrefix() string {
	if x != nil {
		return x.Prefix
	}
	return ""
}

func (x *LogConfig) GetOverrideHandlerPrefix() string {
	if x != nil {
		return x.OverrideHandlerPrefix
	}
	return ""
}

func (x *LogConfig) GetRootsPemFile() []string {
	if x != nil {
		return x.RootsPemFile
	}
	return nil
}

func (x *LogConfig) GetPrivateKey() *any.Any {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *LogConfig) GetPublicKey() *keyspb.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *LogConfig) GetRejectExpired() bool {
	if x != nil {
		return x.RejectExpired
	}
	return false
}

func (x *LogConfig) GetRejectUnexpired() bool {
	if x != nil {
		return x.RejectUnexpired
	}
	return false
}

func (x *LogConfig) GetExtKeyUsages() []string {
	if x != nil {
		return x.ExtKeyUsages
	}
	return nil
}

func (x *LogConfig) GetNotAfterStart() *timestamp.Timestamp {
	if x != nil {
		return x.NotAfterStart
	}
	return nil
}

func (x *LogConfig) GetNotAfterLimit() *timestamp.Timestamp {
	if x != nil {
		return x.NotAfterLimit
	}
	return nil
}

func (x *LogConfig) GetAcceptOnlyCa() bool {
	if x != nil {
		return x.AcceptOnlyCa
	}
	return false
}

func (x *LogConfig) GetLogBackendName() string {
	if x != nil {
		return x.LogBackendName
	}
	return ""
}

func (x *LogConfig) GetIsMirror() bool {
	if x != nil {
		return x.IsMirror
	}
	return false
}

func (x *LogConfig) GetMaxMergeDelaySec() int32 {
	if x != nil {
		return x.MaxMergeDelaySec
	}
	return 0
}

func (x *LogConfig) GetExpectedMergeDelaySec() int32 {
	if x != nil {
		return x.ExpectedMergeDelaySec
	}
	return 0
}

func (x *LogConfig) GetFrozenSth() *SignedTreeHead {
	if x != nil {
		return x.FrozenSth
	}
	return nil
}

func (x *LogConfig) GetRejectExtensions() []string {
	if x != nil {
		return x.RejectExtensions
	}
	return nil
}

// LogMultiConfig wraps up a LogBackendSet and corresponding LogConfigSet so
// that they can easily be parsed as a single proto.
type LogMultiConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The set of backends that this configuration will use to send requests to.
	// The names of the backends in the LogBackendSet must all be distinct.
	Backends *LogBackendSet `protobuf:"bytes,1,opt,name=backends,proto3" json:"backends,omitempty"`
	// The set of logs that will use the above backends. All the protos in this
	// LogConfigSet must set a valid log_backend_name for the config to be usable.
	LogConfigs *LogConfigSet `protobuf:"bytes,2,opt,name=log_configs,json=logConfigs,proto3" json:"log_configs,omitempty"`
}

func (x *LogMultiConfig) Reset() {
	*x = LogMultiConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogMultiConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogMultiConfig) ProtoMessage() {}

func (x *LogMultiConfig) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogMultiConfig.ProtoReflect.Descriptor instead.
func (*LogMultiConfig) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{4}
}

func (x *LogMultiConfig) GetBackends() *LogBackendSet {
	if x != nil {
		return x.Backends
	}
	return nil
}

func (x *LogMultiConfig) GetLogConfigs() *LogConfigSet {
	if x != nil {
		return x.LogConfigs
	}
	return nil
}

// SignedTreeHead represents the structure returned by the get-sth CT method.
// See RFC6962 sections 3.5 and 4.3 for reference.
// TODO(pavelkalinnikov): Find a better place for this type.
type SignedTreeHead struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TreeSize          int64  `protobuf:"varint,1,opt,name=tree_size,json=treeSize,proto3" json:"tree_size,omitempty"`
	Timestamp         int64  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Sha256RootHash    []byte `protobuf:"bytes,3,opt,name=sha256_root_hash,json=sha256RootHash,proto3" json:"sha256_root_hash,omitempty"`
	TreeHeadSignature []byte `protobuf:"bytes,4,opt,name=tree_head_signature,json=treeHeadSignature,proto3" json:"tree_head_signature,omitempty"`
}

func (x *SignedTreeHead) Reset() {
	*x = SignedTreeHead{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedTreeHead) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedTreeHead) ProtoMessage() {}

func (x *SignedTreeHead) ProtoReflect() protoreflect.Message {
	mi := &file_trillian_ctfe_configpb_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedTreeHead.ProtoReflect.Descriptor instead.
func (*SignedTreeHead) Descriptor() ([]byte, []int) {
	return file_trillian_ctfe_configpb_config_proto_rawDescGZIP(), []int{5}
}

func (x *SignedTreeHead) GetTreeSize() int64 {
	if x != nil {
		return x.TreeSize
	}
	return 0
}

func (x *SignedTreeHead) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *SignedTreeHead) GetSha256RootHash() []byte {
	if x != nil {
		return x.Sha256RootHash
	}
	return nil
}

func (x *SignedTreeHead) GetTreeHeadSignature() []byte {
	if x != nil {
		return x.TreeHeadSignature
	}
	return nil
}

var File_trillian_ctfe_configpb_config_proto protoreflect.FileDescriptor

var file_trillian_ctfe_configpb_config_proto_rawDesc = []byte{
	0x0a, 0x23, 0x74, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x63, 0x74, 0x66, 0x65, 0x2f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x1a,
	0x1a, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x6b, 0x65, 0x79, 0x73, 0x70, 0x62, 0x2f, 0x6b,
	0x65, 0x79, 0x73, 0x70, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x43, 0x0a, 0x0a, 0x4c, 0x6f, 0x67, 0x42, 0x61,
	0x63, 0x6b, 0x65, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x62, 0x61, 0x63,
	0x6b, 0x65, 0x6e, 0x64, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x70, 0x65, 0x63, 0x22, 0x3f, 0x0a, 0x0d,
	0x4c, 0x6f, 0x67, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x74, 0x12, 0x2e, 0x0a,
	0x07, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x4c, 0x6f, 0x67, 0x42, 0x61, 0x63,
	0x6b, 0x65, 0x6e, 0x64, 0x52, 0x07, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x22, 0x3b, 0x0a,
	0x0c, 0x4c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x65, 0x74, 0x12, 0x2b, 0x0a,
	0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x4c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0xbc, 0x06, 0x0a, 0x09, 0x4c,
	0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x15, 0x0a, 0x06, 0x6c, 0x6f, 0x67, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x49, 0x64, 0x12,
	0x16, 0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x36, 0x0a, 0x17, 0x6f, 0x76, 0x65, 0x72, 0x72,
	0x69, 0x64, 0x65, 0x5f, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x65, 0x66,
	0x69, 0x78, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x6f, 0x76, 0x65, 0x72, 0x72, 0x69,
	0x64, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12,
	0x24, 0x0a, 0x0e, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x5f, 0x70, 0x65, 0x6d, 0x5f, 0x66, 0x69, 0x6c,
	0x65, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x50, 0x65,
	0x6d, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x35, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79,
	0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x0a,
	0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x11, 0x2e, 0x6b, 0x65, 0x79, 0x73, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x25,
	0x0a, 0x0e, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x45, 0x78,
	0x70, 0x69, 0x72, 0x65, 0x64, 0x12, 0x29, 0x0a, 0x10, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x5f,
	0x75, 0x6e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x18, 0x11, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0f, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x55, 0x6e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64,
	0x12, 0x24, 0x0a, 0x0e, 0x65, 0x78, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x75, 0x73, 0x61, 0x67,
	0x65, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x65, 0x78, 0x74, 0x4b, 0x65, 0x79,
	0x55, 0x73, 0x61, 0x67, 0x65, 0x73, 0x12, 0x42, 0x0a, 0x0f, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66,
	0x74, 0x65, 0x72, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d, 0x6e, 0x6f, 0x74,
	0x41, 0x66, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12, 0x42, 0x0a, 0x0f, 0x6e, 0x6f,
	0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0d, 0x6e, 0x6f, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x24,
	0x0a, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x5f, 0x63, 0x61,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x4f, 0x6e,
	0x6c, 0x79, 0x43, 0x61, 0x12, 0x28, 0x0a, 0x10, 0x6c, 0x6f, 0x67, 0x5f, 0x62, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x6c, 0x6f, 0x67, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x69, 0x73, 0x5f, 0x6d, 0x69, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x08, 0x69, 0x73, 0x4d, 0x69, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2d, 0x0a, 0x13, 0x6d,
	0x61, 0x78, 0x5f, 0x6d, 0x65, 0x72, 0x67, 0x65, 0x5f, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x5f, 0x73,
	0x65, 0x63, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x05, 0x52, 0x10, 0x6d, 0x61, 0x78, 0x4d, 0x65, 0x72,
	0x67, 0x65, 0x44, 0x65, 0x6c, 0x61, 0x79, 0x53, 0x65, 0x63, 0x12, 0x37, 0x0a, 0x18, 0x65, 0x78,
	0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x72, 0x67, 0x65, 0x5f, 0x64, 0x65, 0x6c,
	0x61, 0x79, 0x5f, 0x73, 0x65, 0x63, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x05, 0x52, 0x15, 0x65, 0x78,
	0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x72, 0x67, 0x65, 0x44, 0x65, 0x6c, 0x61, 0x79,
	0x53, 0x65, 0x63, 0x12, 0x37, 0x0a, 0x0a, 0x66, 0x72, 0x6f, 0x7a, 0x65, 0x6e, 0x5f, 0x73, 0x74,
	0x68, 0x18, 0x10, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x70, 0x62, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x65, 0x65, 0x48, 0x65, 0x61,
	0x64, 0x52, 0x09, 0x66, 0x72, 0x6f, 0x7a, 0x65, 0x6e, 0x53, 0x74, 0x68, 0x12, 0x2b, 0x0a, 0x11,
	0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x18, 0x12, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x72, 0x65, 0x6a, 0x65, 0x63, 0x74, 0x45,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x7e, 0x0a, 0x0e, 0x4c, 0x6f, 0x67,
	0x4d, 0x75, 0x6c, 0x74, 0x69, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x33, 0x0a, 0x08, 0x62,
	0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x2e, 0x4c, 0x6f, 0x67, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x53, 0x65, 0x74, 0x52, 0x08, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x73,
	0x12, 0x37, 0x0a, 0x0b, 0x6c, 0x6f, 0x67, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62,
	0x2e, 0x4c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x65, 0x74, 0x52, 0x0a, 0x6c,
	0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x22, 0xa5, 0x01, 0x0a, 0x0e, 0x53, 0x69,
	0x67, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x65, 0x65, 0x48, 0x65, 0x61, 0x64, 0x12, 0x1b, 0x0a, 0x09,
	0x74, 0x72, 0x65, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x08, 0x74, 0x72, 0x65, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x28, 0x0a, 0x10, 0x73, 0x68, 0x61, 0x32, 0x35,
	0x36, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0e, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x52, 0x6f, 0x6f, 0x74, 0x48, 0x61, 0x73,
	0x68, 0x12, 0x2e, 0x0a, 0x13, 0x74, 0x72, 0x65, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x5f, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11,
	0x74, 0x72, 0x65, 0x65, 0x48, 0x65, 0x61, 0x64, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x42, 0x46, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x2d,
	0x67, 0x6f, 0x2f, 0x74, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x2f, 0x63, 0x74, 0x66, 0x65,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_trillian_ctfe_configpb_config_proto_rawDescOnce sync.Once
	file_trillian_ctfe_configpb_config_proto_rawDescData = file_trillian_ctfe_configpb_config_proto_rawDesc
)

func file_trillian_ctfe_configpb_config_proto_rawDescGZIP() []byte {
	file_trillian_ctfe_configpb_config_proto_rawDescOnce.Do(func() {
		file_trillian_ctfe_configpb_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_trillian_ctfe_configpb_config_proto_rawDescData)
	})
	return file_trillian_ctfe_configpb_config_proto_rawDescData
}

var file_trillian_ctfe_configpb_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_trillian_ctfe_configpb_config_proto_goTypes = []interface{}{
	(*LogBackend)(nil),          // 0: configpb.LogBackend
	(*LogBackendSet)(nil),       // 1: configpb.LogBackendSet
	(*LogConfigSet)(nil),        // 2: configpb.LogConfigSet
	(*LogConfig)(nil),           // 3: configpb.LogConfig
	(*LogMultiConfig)(nil),      // 4: configpb.LogMultiConfig
	(*SignedTreeHead)(nil),      // 5: configpb.SignedTreeHead
	(*any.Any)(nil),             // 6: google.protobuf.Any
	(*keyspb.PublicKey)(nil),    // 7: keyspb.PublicKey
	(*timestamp.Timestamp)(nil), // 8: google.protobuf.Timestamp
}
var file_trillian_ctfe_configpb_config_proto_depIdxs = []int32{
	0, // 0: configpb.LogBackendSet.backend:type_name -> configpb.LogBackend
	3, // 1: configpb.LogConfigSet.config:type_name -> configpb.LogConfig
	6, // 2: configpb.LogConfig.private_key:type_name -> google.protobuf.Any
	7, // 3: configpb.LogConfig.public_key:type_name -> keyspb.PublicKey
	8, // 4: configpb.LogConfig.not_after_start:type_name -> google.protobuf.Timestamp
	8, // 5: configpb.LogConfig.not_after_limit:type_name -> google.protobuf.Timestamp
	5, // 6: configpb.LogConfig.frozen_sth:type_name -> configpb.SignedTreeHead
	1, // 7: configpb.LogMultiConfig.backends:type_name -> configpb.LogBackendSet
	2, // 8: configpb.LogMultiConfig.log_configs:type_name -> configpb.LogConfigSet
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_trillian_ctfe_configpb_config_proto_init() }
func file_trillian_ctfe_configpb_config_proto_init() {
	if File_trillian_ctfe_configpb_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_trillian_ctfe_configpb_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogBackend); i {
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
		file_trillian_ctfe_configpb_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogBackendSet); i {
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
		file_trillian_ctfe_configpb_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogConfigSet); i {
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
		file_trillian_ctfe_configpb_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogConfig); i {
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
		file_trillian_ctfe_configpb_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogMultiConfig); i {
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
		file_trillian_ctfe_configpb_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedTreeHead); i {
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
			RawDescriptor: file_trillian_ctfe_configpb_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_trillian_ctfe_configpb_config_proto_goTypes,
		DependencyIndexes: file_trillian_ctfe_configpb_config_proto_depIdxs,
		MessageInfos:      file_trillian_ctfe_configpb_config_proto_msgTypes,
	}.Build()
	File_trillian_ctfe_configpb_config_proto = out.File
	file_trillian_ctfe_configpb_config_proto_rawDesc = nil
	file_trillian_ctfe_configpb_config_proto_goTypes = nil
	file_trillian_ctfe_configpb_config_proto_depIdxs = nil
}
