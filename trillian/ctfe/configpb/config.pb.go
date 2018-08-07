// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

package configpb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import any "github.com/golang/protobuf/ptypes/any"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"
import keyspb "github.com/google/trillian/crypto/keyspb"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type LogBackend struct {
	// name defines the name of the log backend for use in LogConfig messages and must be unique.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// backend_spec defines the RPC endpoint that clients should use to send requests
	// to this log backend. These should be in the same format as rpcBackendFlag in the
	// CTFE main and must not be an empty string.
	BackendSpec          string   `protobuf:"bytes,2,opt,name=backend_spec,json=backendSpec,proto3" json:"backend_spec,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LogBackend) Reset()         { *m = LogBackend{} }
func (m *LogBackend) String() string { return proto.CompactTextString(m) }
func (*LogBackend) ProtoMessage()    {}
func (*LogBackend) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7f570532c1cb7a26, []int{0}
}
func (m *LogBackend) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogBackend.Unmarshal(m, b)
}
func (m *LogBackend) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogBackend.Marshal(b, m, deterministic)
}
func (dst *LogBackend) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogBackend.Merge(dst, src)
}
func (m *LogBackend) XXX_Size() int {
	return xxx_messageInfo_LogBackend.Size(m)
}
func (m *LogBackend) XXX_DiscardUnknown() {
	xxx_messageInfo_LogBackend.DiscardUnknown(m)
}

var xxx_messageInfo_LogBackend proto.InternalMessageInfo

func (m *LogBackend) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LogBackend) GetBackendSpec() string {
	if m != nil {
		return m.BackendSpec
	}
	return ""
}

// LogBackendSet supports a configuration where a single set of frontends handle
// requests for multiple backends. For example this could be used to run different
// backends in different geographic regions.
type LogBackendSet struct {
	Backend              []*LogBackend `protobuf:"bytes,1,rep,name=backend,proto3" json:"backend,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *LogBackendSet) Reset()         { *m = LogBackendSet{} }
func (m *LogBackendSet) String() string { return proto.CompactTextString(m) }
func (*LogBackendSet) ProtoMessage()    {}
func (*LogBackendSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7f570532c1cb7a26, []int{1}
}
func (m *LogBackendSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogBackendSet.Unmarshal(m, b)
}
func (m *LogBackendSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogBackendSet.Marshal(b, m, deterministic)
}
func (dst *LogBackendSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogBackendSet.Merge(dst, src)
}
func (m *LogBackendSet) XXX_Size() int {
	return xxx_messageInfo_LogBackendSet.Size(m)
}
func (m *LogBackendSet) XXX_DiscardUnknown() {
	xxx_messageInfo_LogBackendSet.DiscardUnknown(m)
}

var xxx_messageInfo_LogBackendSet proto.InternalMessageInfo

func (m *LogBackendSet) GetBackend() []*LogBackend {
	if m != nil {
		return m.Backend
	}
	return nil
}

// LogConfigSet is a set of LogConfig messages.
type LogConfigSet struct {
	Config               []*LogConfig `protobuf:"bytes,1,rep,name=config,proto3" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *LogConfigSet) Reset()         { *m = LogConfigSet{} }
func (m *LogConfigSet) String() string { return proto.CompactTextString(m) }
func (*LogConfigSet) ProtoMessage()    {}
func (*LogConfigSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7f570532c1cb7a26, []int{2}
}
func (m *LogConfigSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogConfigSet.Unmarshal(m, b)
}
func (m *LogConfigSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogConfigSet.Marshal(b, m, deterministic)
}
func (dst *LogConfigSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogConfigSet.Merge(dst, src)
}
func (m *LogConfigSet) XXX_Size() int {
	return xxx_messageInfo_LogConfigSet.Size(m)
}
func (m *LogConfigSet) XXX_DiscardUnknown() {
	xxx_messageInfo_LogConfigSet.DiscardUnknown(m)
}

var xxx_messageInfo_LogConfigSet proto.InternalMessageInfo

func (m *LogConfigSet) GetConfig() []*LogConfig {
	if m != nil {
		return m.Config
	}
	return nil
}

// LogConfig describes the configuration options for a log instance.
//
// NEXT_ID: 14
type LogConfig struct {
	// The ID of a Trillian tree that stores the log data. The tree type must be
	// LOG for regular CT logs. For mirror logs it must be either PREORDERED_LOG
	// or LOG, and can change at runtime. CTFE in mirror mode uses only read API
	// which is common for both types.
	LogId int64 `protobuf:"varint,1,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"`
	// prefix is the name of the log. It will come after the global or
	// custom handler prefix. For example if the handler prefix is "/logs"
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
	// Arbitrary environment-specific data. Optional.
	Metadata             *any.Any `protobuf:"bytes,14,opt,name=metadata,proto3" json:"metadata,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LogConfig) Reset()         { *m = LogConfig{} }
func (m *LogConfig) String() string { return proto.CompactTextString(m) }
func (*LogConfig) ProtoMessage()    {}
func (*LogConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7f570532c1cb7a26, []int{3}
}
func (m *LogConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogConfig.Unmarshal(m, b)
}
func (m *LogConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogConfig.Marshal(b, m, deterministic)
}
func (dst *LogConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogConfig.Merge(dst, src)
}
func (m *LogConfig) XXX_Size() int {
	return xxx_messageInfo_LogConfig.Size(m)
}
func (m *LogConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LogConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LogConfig proto.InternalMessageInfo

func (m *LogConfig) GetLogId() int64 {
	if m != nil {
		return m.LogId
	}
	return 0
}

func (m *LogConfig) GetPrefix() string {
	if m != nil {
		return m.Prefix
	}
	return ""
}

func (m *LogConfig) GetOverrideHandlerPrefix() string {
	if m != nil {
		return m.OverrideHandlerPrefix
	}
	return ""
}

func (m *LogConfig) GetRootsPemFile() []string {
	if m != nil {
		return m.RootsPemFile
	}
	return nil
}

func (m *LogConfig) GetPrivateKey() *any.Any {
	if m != nil {
		return m.PrivateKey
	}
	return nil
}

func (m *LogConfig) GetPublicKey() *keyspb.PublicKey {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *LogConfig) GetRejectExpired() bool {
	if m != nil {
		return m.RejectExpired
	}
	return false
}

func (m *LogConfig) GetExtKeyUsages() []string {
	if m != nil {
		return m.ExtKeyUsages
	}
	return nil
}

func (m *LogConfig) GetNotAfterStart() *timestamp.Timestamp {
	if m != nil {
		return m.NotAfterStart
	}
	return nil
}

func (m *LogConfig) GetNotAfterLimit() *timestamp.Timestamp {
	if m != nil {
		return m.NotAfterLimit
	}
	return nil
}

func (m *LogConfig) GetAcceptOnlyCa() bool {
	if m != nil {
		return m.AcceptOnlyCa
	}
	return false
}

func (m *LogConfig) GetLogBackendName() string {
	if m != nil {
		return m.LogBackendName
	}
	return ""
}

func (m *LogConfig) GetIsMirror() bool {
	if m != nil {
		return m.IsMirror
	}
	return false
}

func (m *LogConfig) GetMetadata() *any.Any {
	if m != nil {
		return m.Metadata
	}
	return nil
}

// LogMultiConfig wraps up a LogBackendSet and corresponding LogConfigSet so
// that they can easily be parsed as a single proto.
type LogMultiConfig struct {
	// The set of backends that this configuration will use to send requests to.
	// The names of the backends in the LogBackendSet must all be distinct.
	Backends *LogBackendSet `protobuf:"bytes,1,opt,name=backends,proto3" json:"backends,omitempty"`
	// The set of logs that will use the above backends. All the protos in this
	// LogConfigSet must set a valid log_backend_name for the config to be usable.
	LogConfigs           *LogConfigSet `protobuf:"bytes,2,opt,name=log_configs,json=logConfigs,proto3" json:"log_configs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *LogMultiConfig) Reset()         { *m = LogMultiConfig{} }
func (m *LogMultiConfig) String() string { return proto.CompactTextString(m) }
func (*LogMultiConfig) ProtoMessage()    {}
func (*LogMultiConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7f570532c1cb7a26, []int{4}
}
func (m *LogMultiConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogMultiConfig.Unmarshal(m, b)
}
func (m *LogMultiConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogMultiConfig.Marshal(b, m, deterministic)
}
func (dst *LogMultiConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogMultiConfig.Merge(dst, src)
}
func (m *LogMultiConfig) XXX_Size() int {
	return xxx_messageInfo_LogMultiConfig.Size(m)
}
func (m *LogMultiConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LogMultiConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LogMultiConfig proto.InternalMessageInfo

func (m *LogMultiConfig) GetBackends() *LogBackendSet {
	if m != nil {
		return m.Backends
	}
	return nil
}

func (m *LogMultiConfig) GetLogConfigs() *LogConfigSet {
	if m != nil {
		return m.LogConfigs
	}
	return nil
}

func init() {
	proto.RegisterType((*LogBackend)(nil), "configpb.LogBackend")
	proto.RegisterType((*LogBackendSet)(nil), "configpb.LogBackendSet")
	proto.RegisterType((*LogConfigSet)(nil), "configpb.LogConfigSet")
	proto.RegisterType((*LogConfig)(nil), "configpb.LogConfig")
	proto.RegisterType((*LogMultiConfig)(nil), "configpb.LogMultiConfig")
}

func init() { proto.RegisterFile("config.proto", fileDescriptor_config_7f570532c1cb7a26) }

var fileDescriptor_config_7f570532c1cb7a26 = []byte{
	// 599 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0xdf, 0x6f, 0xd3, 0x3a,
	0x14, 0x56, 0x6f, 0xb7, 0xae, 0x3d, 0xfd, 0x71, 0xef, 0xf5, 0xbd, 0xdb, 0xc2, 0x78, 0xa0, 0x54,
	0x20, 0x55, 0x42, 0x4a, 0xa7, 0x4d, 0x83, 0x07, 0x1e, 0xd0, 0x36, 0x81, 0x40, 0xeb, 0x60, 0x4a,
	0xe1, 0xd9, 0x72, 0x92, 0xd3, 0xcc, 0xcc, 0x89, 0x2d, 0xc7, 0x9d, 0x9a, 0x17, 0xfe, 0x6b, 0xde,
	0x51, 0x6c, 0xa7, 0xd3, 0x60, 0x42, 0x3c, 0x35, 0xe7, 0xfb, 0x71, 0xf4, 0xb9, 0xe7, 0x83, 0x41,
	0x22, 0x8b, 0x25, 0xcf, 0x42, 0xa5, 0xa5, 0x91, 0xa4, 0xeb, 0x26, 0x15, 0x1f, 0x9c, 0x64, 0xdc,
	0x5c, 0xaf, 0xe2, 0x30, 0x91, 0xf9, 0x2c, 0x93, 0x32, 0x13, 0x38, 0x33, 0x9a, 0x0b, 0xc1, 0x59,
	0x31, 0x4b, 0x74, 0xa5, 0x8c, 0x9c, 0xdd, 0x60, 0x55, 0xaa, 0xd8, 0xff, 0xb8, 0x05, 0x07, 0x8f,
	0xbc, 0xd6, 0x4e, 0xf1, 0x6a, 0x39, 0x63, 0x45, 0xe5, 0xa9, 0x27, 0x3f, 0x53, 0x86, 0xe7, 0x58,
	0x1a, 0x96, 0x2b, 0x27, 0x98, 0x9c, 0x03, 0xcc, 0x65, 0x76, 0xc6, 0x92, 0x1b, 0x2c, 0x52, 0x42,
	0x60, 0xab, 0x60, 0x39, 0x06, 0xad, 0x71, 0x6b, 0xda, 0x8b, 0xec, 0x37, 0x79, 0x0a, 0x83, 0xd8,
	0xd1, 0xb4, 0x54, 0x98, 0x04, 0x7f, 0x59, 0xae, 0xef, 0xb1, 0x85, 0xc2, 0x64, 0xf2, 0x06, 0x86,
	0x77, 0x4b, 0x16, 0x68, 0x48, 0x08, 0x3b, 0x9e, 0x0f, 0x5a, 0xe3, 0xf6, 0xb4, 0x7f, 0xf4, 0x7f,
	0xd8, 0x3c, 0x32, 0xbc, 0x53, 0x46, 0x8d, 0x68, 0xf2, 0x1a, 0x06, 0x73, 0x99, 0x9d, 0x5b, 0x49,
	0xed, 0x7f, 0x01, 0x1d, 0xa7, 0xf7, 0xf6, 0xff, 0xee, 0xd9, 0x9d, 0x2e, 0xf2, 0x92, 0xc9, 0xf7,
	0x2d, 0xe8, 0x6d, 0x50, 0xb2, 0x0b, 0x1d, 0x21, 0x33, 0xca, 0x53, 0xfb, 0x88, 0x76, 0xb4, 0x2d,
	0x64, 0xf6, 0x21, 0x25, 0x7b, 0xd0, 0x51, 0x1a, 0x97, 0x7c, 0xed, 0xf3, 0xfb, 0x89, 0xbc, 0x84,
	0x7d, 0x79, 0x8b, 0x5a, 0xf3, 0x14, 0xe9, 0x35, 0x2b, 0x52, 0x81, 0x9a, 0x7a, 0xe1, 0xd0, 0x0a,
	0x77, 0x1b, 0xfa, 0xbd, 0x63, 0xaf, 0x9c, 0xef, 0x19, 0x8c, 0xb4, 0x94, 0xa6, 0xa4, 0x0a, 0x73,
	0xba, 0xe4, 0x02, 0x83, 0xf6, 0xb8, 0x3d, 0xed, 0x45, 0x03, 0x8b, 0x5e, 0x61, 0xfe, 0x8e, 0x0b,
	0x24, 0x27, 0xd0, 0x57, 0x9a, 0xdf, 0x32, 0x83, 0xf4, 0x06, 0xab, 0x60, 0x6b, 0xdc, 0xb2, 0xff,
	0x85, 0x3b, 0x4a, 0xd8, 0x1c, 0x25, 0x3c, 0x2d, 0xaa, 0x08, 0xbc, 0xf0, 0x02, 0x2b, 0x72, 0x08,
	0xa0, 0x56, 0xb1, 0xe0, 0x89, 0x75, 0x6d, 0x5b, 0xd7, 0xbf, 0xa1, 0xbf, 0xf9, 0x95, 0x65, 0x2e,
	0xb0, 0x8a, 0x7a, 0xaa, 0xf9, 0x24, 0xcf, 0x61, 0xa4, 0xf1, 0x2b, 0x26, 0x86, 0xe2, 0x5a, 0x71,
	0x8d, 0x69, 0xd0, 0x19, 0xb7, 0xa6, 0xdd, 0x68, 0xe8, 0xd0, 0xb7, 0x0e, 0xac, 0x53, 0xe3, 0xda,
	0xd4, 0x5b, 0xe9, 0xaa, 0x64, 0x19, 0x96, 0xc1, 0x8e, 0x4b, 0x8d, 0x6b, 0x73, 0x81, 0xd5, 0x17,
	0x8b, 0x91, 0x33, 0xf8, 0xbb, 0x90, 0x86, 0xb2, 0xa5, 0x41, 0x4d, 0x4b, 0xc3, 0xb4, 0x09, 0xba,
	0x36, 0xc3, 0xc1, 0x2f, 0xc9, 0x3f, 0x37, 0x75, 0x8a, 0x86, 0x85, 0x34, 0xa7, 0xb5, 0x63, 0x51,
	0x1b, 0xee, 0xef, 0x10, 0x3c, 0xe7, 0x26, 0xe8, 0xfd, 0xf9, 0x8e, 0x79, 0x6d, 0xa8, 0xd3, 0xb2,
	0x24, 0x41, 0x65, 0xa8, 0x2c, 0x44, 0x45, 0x13, 0x16, 0x80, 0x7d, 0xd4, 0xc0, 0xa1, 0x9f, 0x0a,
	0x51, 0x9d, 0x33, 0x32, 0x85, 0x7f, 0xea, 0x83, 0x37, 0x1d, 0xb5, 0xfd, 0xed, 0xdb, 0xd3, 0x8d,
	0xc4, 0xa6, 0x6a, 0x1f, 0xeb, 0x26, 0x3f, 0x86, 0x1e, 0x2f, 0x69, 0xce, 0xb5, 0x96, 0x3a, 0x18,
	0xd8, 0x55, 0x5d, 0x5e, 0x5e, 0xda, 0x99, 0x1c, 0x42, 0x37, 0x47, 0xc3, 0x52, 0x66, 0x58, 0x30,
	0xfa, 0xcd, 0x9d, 0x36, 0xaa, 0xc9, 0x37, 0x18, 0xcd, 0x65, 0x76, 0xb9, 0x12, 0x86, 0xfb, 0xee,
	0x1d, 0x43, 0xd7, 0xc7, 0x28, 0x6d, 0xfb, 0xfa, 0x47, 0xfb, 0x0f, 0xf5, 0x7e, 0x81, 0x26, 0xda,
	0x08, 0xc9, 0x2b, 0xe8, 0xd7, 0xf9, 0x9d, 0xae, 0xb4, 0xf5, 0xec, 0x1f, 0xed, 0x3d, 0x50, 0xf8,
	0xda, 0x06, 0xa2, 0x99, 0xca, 0xb8, 0x63, 0x73, 0x1d, 0xff, 0x08, 0x00, 0x00, 0xff, 0xff, 0x9d,
	0x1f, 0x0e, 0x1b, 0x4e, 0x04, 0x00, 0x00,
}
