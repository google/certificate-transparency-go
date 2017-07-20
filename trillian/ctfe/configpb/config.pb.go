// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

/*
Package configpb is a generated protocol buffer package.

It is generated from these files:
	config.proto

It has these top-level messages:
	LogConfig
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

// LogConfig describes the configuration options for a log instance.
type LogConfig struct {
	LogId        int64                `protobuf:"varint,1,opt,name=log_id,json=logId" json:"log_id,omitempty"`
	Prefix       string               `protobuf:"bytes,2,opt,name=prefix" json:"prefix,omitempty"`
	RootsPemFile []string             `protobuf:"bytes,3,rep,name=roots_pem_file,json=rootsPemFile" json:"roots_pem_file,omitempty"`
	PrivateKey   *google_protobuf.Any `protobuf:"bytes,4,opt,name=private_key,json=privateKey" json:"private_key,omitempty"`
	// The public key is included for the convenience of test tools (and obviously
	// should match the private key above); it is not used by the CT personality.
	PublicKey     *keyspb.PublicKey `protobuf:"bytes,5,opt,name=public_key,json=publicKey" json:"public_key,omitempty"`
	RejectExpired bool              `protobuf:"varint,6,opt,name=reject_expired,json=rejectExpired" json:"reject_expired,omitempty"`
	ExtKeyUsages  []string          `protobuf:"bytes,7,rep,name=ext_key_usages,json=extKeyUsages" json:"ext_key_usages,omitempty"`
	// not_after_start defines the start of the range of acceptable NotAfter
	// values, inclusive.
	NotAfterStart *google_protobuf1.Timestamp `protobuf:"bytes,8,opt,name=not_after_start,json=notAfterStart" json:"not_after_start,omitempty"`
	// not_after_limit defines the end of the range of acceptable NotAfter values,
	// exlusive.
	NotAfterLimit *google_protobuf1.Timestamp `protobuf:"bytes,9,opt,name=not_after_limit,json=notAfterLimit" json:"not_after_limit,omitempty"`
	// accept_only_ca controls whether or not *only* certificates with the CA bit
	// set will be accepted.
	AcceptOnlyCa bool `protobuf:"varint,10,opt,name=accept_only_ca,json=acceptOnlyCa" json:"accept_only_ca,omitempty"`
}

func (m *LogConfig) Reset()                    { *m = LogConfig{} }
func (m *LogConfig) String() string            { return proto.CompactTextString(m) }
func (*LogConfig) ProtoMessage()               {}
func (*LogConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

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

func init() {
	proto.RegisterType((*LogConfig)(nil), "configpb.LogConfig")
}

func init() { proto.RegisterFile("config.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 384 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0x51, 0x8b, 0xd4, 0x30,
	0x14, 0x85, 0xa9, 0xe3, 0x8e, 0xd3, 0xec, 0xec, 0x8a, 0x45, 0x25, 0xce, 0x8b, 0x45, 0x14, 0xfa,
	0xd4, 0x8a, 0xb2, 0x3f, 0x60, 0x5d, 0x14, 0x64, 0x16, 0x5c, 0xaa, 0x3e, 0x87, 0x34, 0x73, 0x1b,
	0xe3, 0xa4, 0x49, 0x48, 0xef, 0xc8, 0xe4, 0xff, 0xf9, 0xc3, 0xa4, 0x49, 0xe7, 0x41, 0x7d, 0xd9,
	0xa7, 0xf6, 0x9e, 0x7b, 0xce, 0xe1, 0xbb, 0x21, 0x6b, 0x61, 0x4d, 0xaf, 0x64, 0xed, 0xbc, 0x45,
	0x5b, 0xac, 0xd2, 0xe4, 0xba, 0xcd, 0x95, 0x54, 0xf8, 0xe3, 0xd0, 0xd5, 0xc2, 0x0e, 0x8d, 0xb4,
	0x56, 0x6a, 0x68, 0xd0, 0x2b, 0xad, 0x15, 0x37, 0x8d, 0xf0, 0xc1, 0xa1, 0x6d, 0xf6, 0x10, 0x46,
	0xd7, 0xcd, 0x9f, 0x54, 0xb0, 0x79, 0x31, 0x7b, 0xe3, 0xd4, 0x1d, 0xfa, 0x86, 0x9b, 0x30, 0xaf,
	0x5e, 0xfe, 0xbb, 0x42, 0x35, 0xc0, 0x88, 0x7c, 0x70, 0xc9, 0xf0, 0xea, 0xf7, 0x82, 0xe4, 0xb7,
	0x56, 0xde, 0x44, 0x84, 0xe2, 0x19, 0x59, 0x6a, 0x2b, 0x99, 0xda, 0xd1, 0xac, 0xcc, 0xaa, 0x45,
	0x7b, 0xa6, 0xad, 0xfc, 0xbc, 0x2b, 0x9e, 0x93, 0xa5, 0xf3, 0xd0, 0xab, 0x23, 0x7d, 0x50, 0x66,
	0x55, 0xde, 0xce, 0x53, 0xf1, 0x9a, 0x5c, 0x7a, 0x6b, 0x71, 0x64, 0x0e, 0x06, 0xd6, 0x2b, 0x0d,
	0x74, 0x51, 0x2e, 0xaa, 0xbc, 0x5d, 0x47, 0xf5, 0x0e, 0x86, 0x4f, 0x4a, 0x43, 0x71, 0x45, 0xce,
	0x9d, 0x57, 0xbf, 0x38, 0x02, 0xdb, 0x43, 0xa0, 0x0f, 0xcb, 0xac, 0x3a, 0x7f, 0xf7, 0xb4, 0x4e,
	0x64, 0xf5, 0x89, 0xac, 0xbe, 0x36, 0xa1, 0x25, 0xb3, 0x71, 0x0b, 0xa1, 0x78, 0x4b, 0x88, 0x3b,
	0x74, 0x5a, 0x89, 0x98, 0x3a, 0x8b, 0xa9, 0x27, 0xf5, 0x7c, 0xf8, 0x5d, 0xdc, 0x6c, 0x21, 0xb4,
	0xb9, 0x3b, 0xfd, 0x16, 0x6f, 0xc8, 0xa5, 0x87, 0x9f, 0x20, 0x90, 0xc1, 0xd1, 0x29, 0x0f, 0x3b,
	0xba, 0x2c, 0xb3, 0x6a, 0xd5, 0x5e, 0x24, 0xf5, 0x63, 0x12, 0x27, 0x6a, 0x38, 0xe2, 0xd4, 0xca,
	0x0e, 0x23, 0x97, 0x30, 0xd2, 0x47, 0x89, 0x1a, 0x8e, 0xb8, 0x85, 0xf0, 0x3d, 0x6a, 0xc5, 0x07,
	0xf2, 0xd8, 0x58, 0x64, 0xbc, 0x47, 0xf0, 0x6c, 0x44, 0xee, 0x91, 0xae, 0x22, 0xc3, 0xe6, 0x3f,
	0xf2, 0x6f, 0xa7, 0x37, 0x6d, 0x2f, 0x8c, 0xc5, 0xeb, 0x29, 0xf1, 0x75, 0x0a, 0xfc, 0xdd, 0xa1,
	0xd5, 0xa0, 0x90, 0xe6, 0xf7, 0xef, 0xb8, 0x9d, 0x02, 0x13, 0x2d, 0x17, 0x02, 0x1c, 0x32, 0x6b,
	0x74, 0x60, 0x82, 0x53, 0x12, 0x8f, 0x5a, 0x27, 0xf5, 0x8b, 0xd1, 0xe1, 0x86, 0x77, 0xcb, 0x58,
	0xf4, 0xfe, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x8b, 0x4d, 0xc8, 0x5a, 0x02, 0x00, 0x00,
}
