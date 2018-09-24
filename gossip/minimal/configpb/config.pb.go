// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

package configpb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import any "github.com/golang/protobuf/ptypes/any"
import duration "github.com/golang/protobuf/ptypes/duration"
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

// LogConfig describes the configuration options for a Log.
type LogConfig struct {
	// Human-readable name for the log; must be unique
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Base URL for the log.
	Url string `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`
	// Log's public key. This is optional, but if omitted signatures from
	// the log will not be checked.
	PublicKey *keyspb.PublicKey `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// Minimum interval between requests to the log, for rate limiting.
	MinReqInterval       *duration.Duration `protobuf:"bytes,4,opt,name=min_req_interval,json=minReqInterval,proto3" json:"min_req_interval,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *LogConfig) Reset()         { *m = LogConfig{} }
func (m *LogConfig) String() string { return proto.CompactTextString(m) }
func (*LogConfig) ProtoMessage()    {}
func (*LogConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_3eaf2c85e69e9ea4, []int{0}
}
func (m *LogConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogConfig.Unmarshal(m, b)
}
func (m *LogConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogConfig.Marshal(b, m, deterministic)
}
func (m *LogConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogConfig.Merge(m, src)
}
func (m *LogConfig) XXX_Size() int {
	return xxx_messageInfo_LogConfig.Size(m)
}
func (m *LogConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_LogConfig.DiscardUnknown(m)
}

var xxx_messageInfo_LogConfig proto.InternalMessageInfo

func (m *LogConfig) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LogConfig) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *LogConfig) GetPublicKey() *keyspb.PublicKey {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *LogConfig) GetMinReqInterval() *duration.Duration {
	if m != nil {
		return m.MinReqInterval
	}
	return nil
}

// GossipConfig describes the configuration of a gossiper.
type GossipConfig struct {
	// The source logs whose STHs will be logged.
	SourceLog []*LogConfig `protobuf:"bytes,1,rep,name=source_log,json=sourceLog,proto3" json:"source_log,omitempty"`
	// The destination hubs to which the minimal-gossip certificates will
	// be submitted.  These destination hubs need to be configured to accept
	// root_cert as an acceptable root.
	DestHub []*LogConfig `protobuf:"bytes,2,rep,name=dest_hub,json=destHub,proto3" json:"dest_hub,omitempty"`
	// The root certificate used for submissions, in PEM format; this should
	// include the public key corresponding to private_key below.
	RootCert string `protobuf:"bytes,3,opt,name=root_cert,json=rootCert,proto3" json:"root_cert,omitempty"`
	// The private key that will be used to sign synthetic leaf certificates
	// that chain to the root_cert.
	PrivateKey *any.Any `protobuf:"bytes,4,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// Number of buffered STHs allowed.
	// TODO(drysdale): investigate sensible ranges for this.
	BufferSize           int32    `protobuf:"varint,5,opt,name=buffer_size,json=bufferSize,proto3" json:"buffer_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GossipConfig) Reset()         { *m = GossipConfig{} }
func (m *GossipConfig) String() string { return proto.CompactTextString(m) }
func (*GossipConfig) ProtoMessage()    {}
func (*GossipConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_3eaf2c85e69e9ea4, []int{1}
}
func (m *GossipConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GossipConfig.Unmarshal(m, b)
}
func (m *GossipConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GossipConfig.Marshal(b, m, deterministic)
}
func (m *GossipConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GossipConfig.Merge(m, src)
}
func (m *GossipConfig) XXX_Size() int {
	return xxx_messageInfo_GossipConfig.Size(m)
}
func (m *GossipConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_GossipConfig.DiscardUnknown(m)
}

var xxx_messageInfo_GossipConfig proto.InternalMessageInfo

func (m *GossipConfig) GetSourceLog() []*LogConfig {
	if m != nil {
		return m.SourceLog
	}
	return nil
}

func (m *GossipConfig) GetDestHub() []*LogConfig {
	if m != nil {
		return m.DestHub
	}
	return nil
}

func (m *GossipConfig) GetRootCert() string {
	if m != nil {
		return m.RootCert
	}
	return ""
}

func (m *GossipConfig) GetPrivateKey() *any.Any {
	if m != nil {
		return m.PrivateKey
	}
	return nil
}

func (m *GossipConfig) GetBufferSize() int32 {
	if m != nil {
		return m.BufferSize
	}
	return 0
}

// GoshawkConfig describes the configuration of a gossiper.
type GoshawkConfig struct {
	// The source logs whose STHs will be checked.
	SourceLog []*LogConfig `protobuf:"bytes,1,rep,name=source_log,json=sourceLog,proto3" json:"source_log,omitempty"`
	// The destination hub which will be scanned for minimal-gossip certificates.
	DestHub *LogConfig `protobuf:"bytes,2,opt,name=dest_hub,json=destHub,proto3" json:"dest_hub,omitempty"`
	// Number of STHs pending verification that can be buffered up for each source log.
	BufferSize           int32    `protobuf:"varint,5,opt,name=buffer_size,json=bufferSize,proto3" json:"buffer_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GoshawkConfig) Reset()         { *m = GoshawkConfig{} }
func (m *GoshawkConfig) String() string { return proto.CompactTextString(m) }
func (*GoshawkConfig) ProtoMessage()    {}
func (*GoshawkConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_3eaf2c85e69e9ea4, []int{2}
}
func (m *GoshawkConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GoshawkConfig.Unmarshal(m, b)
}
func (m *GoshawkConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GoshawkConfig.Marshal(b, m, deterministic)
}
func (m *GoshawkConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GoshawkConfig.Merge(m, src)
}
func (m *GoshawkConfig) XXX_Size() int {
	return xxx_messageInfo_GoshawkConfig.Size(m)
}
func (m *GoshawkConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_GoshawkConfig.DiscardUnknown(m)
}

var xxx_messageInfo_GoshawkConfig proto.InternalMessageInfo

func (m *GoshawkConfig) GetSourceLog() []*LogConfig {
	if m != nil {
		return m.SourceLog
	}
	return nil
}

func (m *GoshawkConfig) GetDestHub() *LogConfig {
	if m != nil {
		return m.DestHub
	}
	return nil
}

func (m *GoshawkConfig) GetBufferSize() int32 {
	if m != nil {
		return m.BufferSize
	}
	return 0
}

func init() {
	proto.RegisterType((*LogConfig)(nil), "configpb.LogConfig")
	proto.RegisterType((*GossipConfig)(nil), "configpb.GossipConfig")
	proto.RegisterType((*GoshawkConfig)(nil), "configpb.GoshawkConfig")
}

func init() { proto.RegisterFile("config.proto", fileDescriptor_3eaf2c85e69e9ea4) }

var fileDescriptor_3eaf2c85e69e9ea4 = []byte{
	// 388 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x90, 0xc1, 0x6e, 0x13, 0x31,
	0x10, 0x86, 0xe5, 0xa6, 0x85, 0xec, 0xa4, 0xa0, 0x62, 0x38, 0x6c, 0x8b, 0x04, 0x51, 0x4e, 0x39,
	0x79, 0x51, 0x50, 0x1f, 0x00, 0x05, 0xa9, 0x20, 0x7a, 0x40, 0xe6, 0x01, 0x56, 0xeb, 0xed, 0x64,
	0x63, 0x65, 0xe3, 0x71, 0xbd, 0x76, 0xd1, 0xf6, 0x39, 0x78, 0x08, 0xde, 0x8c, 0xd7, 0x40, 0xeb,
	0x75, 0x38, 0x80, 0x50, 0x2f, 0x3d, 0x79, 0x66, 0xfe, 0x7f, 0xac, 0xff, 0x1b, 0x38, 0xad, 0xc9,
	0x6c, 0x74, 0x23, 0xac, 0x23, 0x4f, 0x7c, 0x3a, 0x76, 0x56, 0x5d, 0x5c, 0x36, 0xda, 0x6f, 0x83,
	0x12, 0x35, 0xed, 0x8b, 0x86, 0xa8, 0x69, 0xb1, 0xf0, 0x4e, 0xb7, 0xad, 0xae, 0x4c, 0x51, 0xbb,
	0xde, 0x7a, 0x2a, 0x76, 0xd8, 0x77, 0x56, 0xa5, 0x67, 0xfc, 0xe0, 0xe2, 0x3c, 0x79, 0x63, 0xa7,
	0xc2, 0xa6, 0xa8, 0x4c, 0x9f, 0xa4, 0x37, 0x7f, 0x4b, 0x37, 0xc1, 0x55, 0x5e, 0x93, 0x19, 0xf5,
	0xc5, 0x4f, 0x06, 0xd9, 0x35, 0x35, 0xeb, 0x98, 0x80, 0x73, 0x38, 0x36, 0xd5, 0x1e, 0x73, 0x36,
	0x67, 0xcb, 0x4c, 0xc6, 0x9a, 0x9f, 0xc1, 0x24, 0xb8, 0x36, 0x3f, 0x8a, 0xa3, 0xa1, 0xe4, 0xef,
	0x00, 0x6c, 0x50, 0xad, 0xae, 0xcb, 0x1d, 0xf6, 0xf9, 0x64, 0xce, 0x96, 0xb3, 0xd5, 0x0b, 0x91,
	0x12, 0x7d, 0x8d, 0xca, 0x17, 0xec, 0x65, 0x66, 0x0f, 0x25, 0x5f, 0xc3, 0xd9, 0x5e, 0x9b, 0xd2,
	0xe1, 0x6d, 0xa9, 0x8d, 0x47, 0x77, 0x57, 0xb5, 0xf9, 0x71, 0xdc, 0x3b, 0x17, 0x63, 0x40, 0x71,
	0x08, 0x28, 0x3e, 0xa6, 0x80, 0xf2, 0xf9, 0x5e, 0x1b, 0x89, 0xb7, 0x9f, 0xd3, 0xc2, 0xe2, 0x17,
	0x83, 0xd3, 0x2b, 0xea, 0x3a, 0x6d, 0x53, 0xda, 0x15, 0x40, 0x47, 0xc1, 0xd5, 0x58, 0xb6, 0xd4,
	0xe4, 0x6c, 0x3e, 0x59, 0xce, 0x56, 0x2f, 0xc5, 0xe1, 0x98, 0xe2, 0x0f, 0x96, 0xcc, 0x46, 0xdb,
	0x35, 0x35, 0x5c, 0xc0, 0xf4, 0x06, 0x3b, 0x5f, 0x6e, 0x83, 0xca, 0x8f, 0xfe, 0xbf, 0xf1, 0x74,
	0x30, 0x7d, 0x0a, 0x8a, 0xbf, 0x86, 0xcc, 0x11, 0xf9, 0xb2, 0x46, 0xe7, 0x23, 0x6a, 0x26, 0xa7,
	0xc3, 0x60, 0x8d, 0xce, 0xf3, 0x4b, 0x98, 0x59, 0xa7, 0xef, 0x2a, 0x8f, 0xf1, 0x12, 0x23, 0xd1,
	0xab, 0x7f, 0x88, 0x3e, 0x98, 0x5e, 0x42, 0x32, 0x0e, 0xd7, 0x78, 0x0b, 0x33, 0x15, 0x36, 0x1b,
	0x74, 0x65, 0xa7, 0xef, 0x31, 0x3f, 0x99, 0xb3, 0xe5, 0x89, 0x84, 0x71, 0xf4, 0x4d, 0xdf, 0xe3,
	0xe2, 0x07, 0x83, 0x67, 0x57, 0xd4, 0x6d, 0xab, 0xef, 0xbb, 0x47, 0x43, 0x65, 0x0f, 0xa2, 0x3e,
	0x14, 0x4b, 0x3d, 0x89, 0x44, 0xef, 0x7f, 0x07, 0x00, 0x00, 0xff, 0xff, 0x95, 0x19, 0x54, 0x22,
	0xbe, 0x02, 0x00, 0x00,
}
