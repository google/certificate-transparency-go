// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

/*
Package configpb is a generated protocol buffer package.

It is generated from these files:
	config.proto

It has these top-level messages:
	LogBackend
	LogBackendSet
	LogConfigSet
	LogConfig
	LogMultiConfig
*/
package configpb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import keyspb "github.com/google/trillian/crypto/keyspb"
import google_protobuf "github.com/golang/protobuf/ptypes/any"
import google_protobuf1 "github.com/golang/protobuf/ptypes/timestamp"

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
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// backend_spec defines the RPC endpoint that clients should use to send requests
	// to this log backend. These should be in the same format as rpcBackendFlag in the
	// CTFE main and must not be an empty string.
	BackendSpec string `protobuf:"bytes,2,opt,name=backend_spec,json=backendSpec" json:"backend_spec,omitempty"`
}

func (m *LogBackend) Reset()                    { *m = LogBackend{} }
func (m *LogBackend) String() string            { return proto.CompactTextString(m) }
func (*LogBackend) ProtoMessage()               {}
func (*LogBackend) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

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
	Backend []*LogBackend `protobuf:"bytes,1,rep,name=backend" json:"backend,omitempty"`
}

func (m *LogBackendSet) Reset()                    { *m = LogBackendSet{} }
func (m *LogBackendSet) String() string            { return proto.CompactTextString(m) }
func (*LogBackendSet) ProtoMessage()               {}
func (*LogBackendSet) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *LogBackendSet) GetBackend() []*LogBackend {
	if m != nil {
		return m.Backend
	}
	return nil
}

// LogConfigSet is a set of LogConfig messages.
type LogConfigSet struct {
	Config []*LogConfig `protobuf:"bytes,1,rep,name=config" json:"config,omitempty"`
}

func (m *LogConfigSet) Reset()                    { *m = LogConfigSet{} }
func (m *LogConfigSet) String() string            { return proto.CompactTextString(m) }
func (*LogConfigSet) ProtoMessage()               {}
func (*LogConfigSet) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *LogConfigSet) GetConfig() []*LogConfig {
	if m != nil {
		return m.Config
	}
	return nil
}

// LogConfig describes the configuration options for a log instance.
type LogConfig struct {
	LogId        int64                `protobuf:"varint,1,opt,name=log_id,json=logId" json:"log_id,omitempty"`
	Prefix       string               `protobuf:"bytes,2,opt,name=prefix" json:"prefix,omitempty"`
	RootsPemFile []string             `protobuf:"bytes,3,rep,name=roots_pem_file,json=rootsPemFile" json:"roots_pem_file,omitempty"`
	PrivateKey   *google_protobuf.Any `protobuf:"bytes,4,opt,name=private_key,json=privateKey" json:"private_key,omitempty"`
	// The public key is included for the convenience of test tools (and obviously
	// should match the private key above); it is not used by the CT personality.
	PublicKey *keyspb.PublicKey `protobuf:"bytes,5,opt,name=public_key,json=publicKey" json:"public_key,omitempty"`
	// If reject_expired is true then the certificate validity period will be
	// checked during the validation of submissions. This will cause expired
	// certificates to be rejected.
	RejectExpired bool `protobuf:"varint,6,opt,name=reject_expired,json=rejectExpired" json:"reject_expired,omitempty"`
	// If set ext_key_usages will restrict the set of such usages that the
	// server will accept. By default all are accepted. The values specified
	// must be ones known to the x509 package.
	ExtKeyUsages []string `protobuf:"bytes,7,rep,name=ext_key_usages,json=extKeyUsages" json:"ext_key_usages,omitempty"`
	// not_after_start defines the start of the range of acceptable NotAfter
	// values, inclusive.
	// Leaving this unset implies no lower bound to the range.
	NotAfterStart *google_protobuf1.Timestamp `protobuf:"bytes,8,opt,name=not_after_start,json=notAfterStart" json:"not_after_start,omitempty"`
	// not_after_limit defines the end of the range of acceptable NotAfter values,
	// exclusive.
	// Leaving this unset implies no upper bound to the range.
	NotAfterLimit *google_protobuf1.Timestamp `protobuf:"bytes,9,opt,name=not_after_limit,json=notAfterLimit" json:"not_after_limit,omitempty"`
	// accept_only_ca controls whether or not *only* certificates with the CA bit
	// set will be accepted.
	AcceptOnlyCa bool `protobuf:"varint,10,opt,name=accept_only_ca,json=acceptOnlyCa" json:"accept_only_ca,omitempty"`
	// backend_name if set indicates which backend serves this log. The name must be
	// one of those defined in the LogBackendSet.
	LogBackendName string `protobuf:"bytes,11,opt,name=log_backend_name,json=logBackendName" json:"log_backend_name,omitempty"`
}

func (m *LogConfig) Reset()                    { *m = LogConfig{} }
func (m *LogConfig) String() string            { return proto.CompactTextString(m) }
func (*LogConfig) ProtoMessage()               {}
func (*LogConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

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

func (m *LogConfig) GetRootsPemFile() []string {
	if m != nil {
		return m.RootsPemFile
	}
	return nil
}

func (m *LogConfig) GetPrivateKey() *google_protobuf.Any {
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

func (m *LogConfig) GetNotAfterStart() *google_protobuf1.Timestamp {
	if m != nil {
		return m.NotAfterStart
	}
	return nil
}

func (m *LogConfig) GetNotAfterLimit() *google_protobuf1.Timestamp {
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

// LogMultiConfig wraps up a LogBackendSet and corresponding LogConfigSet so
// that they can easily be parsed as a single proto.
type LogMultiConfig struct {
	// The set of backends that this configuration will use to send requests to.
	// The names of the backends in the LogBackendSet must all be distinct.
	Backends *LogBackendSet `protobuf:"bytes,1,opt,name=backends" json:"backends,omitempty"`
	// The set of logs that will use the above backends. All the protos in this
	// LogConfigSet must set a valid log_backend_name for the config to be usable.
	LogConfigs *LogConfigSet `protobuf:"bytes,2,opt,name=log_configs,json=logConfigs" json:"log_configs,omitempty"`
}

func (m *LogMultiConfig) Reset()                    { *m = LogMultiConfig{} }
func (m *LogMultiConfig) String() string            { return proto.CompactTextString(m) }
func (*LogMultiConfig) ProtoMessage()               {}
func (*LogMultiConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

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

func init() { proto.RegisterFile("config.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 540 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x41, 0x6f, 0xd3, 0x4c,
	0x10, 0x55, 0xbe, 0xb4, 0x69, 0x32, 0x4e, 0xf3, 0xc1, 0x02, 0xc5, 0xe4, 0x42, 0x88, 0x40, 0x8a,
	0x84, 0xe4, 0xa0, 0x54, 0x15, 0x07, 0x0e, 0xa8, 0x8d, 0x40, 0x42, 0x09, 0x50, 0x39, 0x70, 0x5e,
	0xad, 0x37, 0x13, 0xb3, 0x64, 0xed, 0x5d, 0xd9, 0x1b, 0x14, 0x5f, 0xf8, 0xc9, 0xfc, 0x06, 0xe4,
	0xdd, 0x75, 0xaa, 0x42, 0x0f, 0x9c, 0xe2, 0x79, 0xf3, 0xde, 0xe4, 0xcd, 0xce, 0x83, 0x3e, 0x57,
	0xf9, 0x46, 0xa4, 0x91, 0x2e, 0x94, 0x51, 0xa4, 0xeb, 0x2a, 0x9d, 0x0c, 0x2f, 0x52, 0x61, 0xbe,
	0xed, 0x92, 0x88, 0xab, 0x6c, 0x9a, 0x2a, 0x95, 0x4a, 0x9c, 0x9a, 0x42, 0x48, 0x29, 0x58, 0x3e,
	0xe5, 0x45, 0xa5, 0x8d, 0x9a, 0x6e, 0xb1, 0x2a, 0x75, 0xe2, 0x7f, 0xdc, 0x80, 0xe1, 0x13, 0xcf,
	0xb5, 0x55, 0xb2, 0xdb, 0x4c, 0x59, 0x5e, 0xf9, 0xd6, 0xd3, 0x3f, 0x5b, 0x46, 0x64, 0x58, 0x1a,
	0x96, 0x69, 0x47, 0x18, 0xcf, 0x01, 0x96, 0x2a, 0xbd, 0x62, 0x7c, 0x8b, 0xf9, 0x9a, 0x10, 0x38,
	0xca, 0x59, 0x86, 0x61, 0x6b, 0xd4, 0x9a, 0xf4, 0x62, 0xfb, 0x4d, 0x9e, 0x41, 0x3f, 0x71, 0x6d,
	0x5a, 0x6a, 0xe4, 0xe1, 0x7f, 0xb6, 0x17, 0x78, 0x6c, 0xa5, 0x91, 0x8f, 0xdf, 0xc2, 0xe9, 0xcd,
	0x90, 0x15, 0x1a, 0x12, 0xc1, 0x89, 0xef, 0x87, 0xad, 0x51, 0x7b, 0x12, 0xcc, 0x1e, 0x46, 0xcd,
	0x92, 0xd1, 0x0d, 0x33, 0x6e, 0x48, 0xe3, 0x37, 0xd0, 0x5f, 0xaa, 0x74, 0x6e, 0x29, 0xb5, 0xfe,
	0x25, 0x74, 0x1c, 0xdf, 0xcb, 0x1f, 0xdc, 0x92, 0x3b, 0x5e, 0xec, 0x29, 0xe3, 0x5f, 0x6d, 0xe8,
	0x1d, 0x50, 0xf2, 0x08, 0x3a, 0x52, 0xa5, 0x54, 0xac, 0xed, 0x12, 0xed, 0xf8, 0x58, 0xaa, 0xf4,
	0xc3, 0x9a, 0x9c, 0x41, 0x47, 0x17, 0xb8, 0x11, 0x7b, 0xef, 0xdf, 0x57, 0xe4, 0x39, 0x0c, 0x0a,
	0xa5, 0x4c, 0x49, 0x35, 0x66, 0x74, 0x23, 0x24, 0x86, 0xed, 0x51, 0x7b, 0xd2, 0x8b, 0xfb, 0x16,
	0xbd, 0xc6, 0xec, 0xbd, 0x90, 0x48, 0x2e, 0x20, 0xd0, 0x85, 0xf8, 0xc1, 0x0c, 0xd2, 0x2d, 0x56,
	0xe1, 0xd1, 0xa8, 0x65, 0x77, 0x72, 0x8f, 0x1b, 0x35, 0x8f, 0x1b, 0x5d, 0xe6, 0x55, 0x0c, 0x9e,
	0xb8, 0xc0, 0x8a, 0xbc, 0x02, 0xd0, 0xbb, 0x44, 0x0a, 0x6e, 0x55, 0xc7, 0x56, 0x75, 0x3f, 0xf2,
	0xb7, 0xbb, 0xb6, 0x9d, 0x05, 0x56, 0x71, 0x4f, 0x37, 0x9f, 0xe4, 0x05, 0x0c, 0x0a, 0xfc, 0x8e,
	0xdc, 0x50, 0xdc, 0x6b, 0x51, 0xe0, 0x3a, 0xec, 0x8c, 0x5a, 0x93, 0x6e, 0x7c, 0xea, 0xd0, 0x77,
	0x0e, 0xac, 0x5d, 0xe3, 0xde, 0xd4, 0x53, 0xe9, 0xae, 0x64, 0x29, 0x96, 0xe1, 0x89, 0x73, 0x8d,
	0x7b, 0xb3, 0xc0, 0xea, 0xab, 0xc5, 0xc8, 0x15, 0xfc, 0x9f, 0x2b, 0x43, 0xd9, 0xc6, 0x60, 0x41,
	0x4b, 0xc3, 0x0a, 0x13, 0x76, 0xad, 0x87, 0xe1, 0x5f, 0xce, 0xbf, 0x34, 0xb1, 0x88, 0x4f, 0x73,
	0x65, 0x2e, 0x6b, 0xc5, 0xaa, 0x16, 0xdc, 0x9e, 0x21, 0x45, 0x26, 0x4c, 0xd8, 0xfb, 0xf7, 0x19,
	0xcb, 0x5a, 0x50, 0xbb, 0x65, 0x9c, 0xa3, 0x36, 0x54, 0xe5, 0xb2, 0xa2, 0x9c, 0x85, 0x60, 0x97,
	0xea, 0x3b, 0xf4, 0x73, 0x2e, 0xab, 0x39, 0x23, 0x13, 0xb8, 0x57, 0x1f, 0xae, 0xc9, 0x9a, 0xcd,
	0x61, 0x60, 0x6f, 0x35, 0x90, 0x87, 0xc8, 0x7c, 0x62, 0x19, 0x8e, 0x7f, 0xc2, 0x60, 0xa9, 0xd2,
	0x8f, 0x3b, 0x69, 0x84, 0x3f, 0xfa, 0x39, 0x74, 0xbd, 0xae, 0xb4, 0x67, 0x0f, 0x66, 0x8f, 0xef,
	0x0a, 0xdc, 0x0a, 0x4d, 0x7c, 0x20, 0x92, 0xd7, 0x10, 0xd4, 0x7f, 0xe8, 0x78, 0xa5, 0xcd, 0x45,
	0x30, 0x3b, 0xbb, 0x23, 0x69, 0xb5, 0x0c, 0x64, 0x53, 0x95, 0x49, 0xc7, 0xae, 0x7c, 0xfe, 0x3b,
	0x00, 0x00, 0xff, 0xff, 0xe6, 0x9e, 0x0d, 0xca, 0xc7, 0x03, 0x00, 0x00,
}
