// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

package configpb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
	duration "github.com/golang/protobuf/ptypes/duration"
	keyspb "github.com/google/trillian/crypto/keyspb"
	math "math"
)

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
	// The destination logs to which the minimal-gossip certificates will
	// be submitted.  These destination logs need to be configured to accept
	// root_cert as an acceptable root.
	DestLog []*LogConfig `protobuf:"bytes,2,rep,name=dest_log,json=destLog,proto3" json:"dest_log,omitempty"`
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

func (m *GossipConfig) GetDestLog() []*LogConfig {
	if m != nil {
		return m.DestLog
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
	// The destination log which will be scanned for minimal-gossip certificates.
	DestLog *LogConfig `protobuf:"bytes,2,opt,name=dest_log,json=destLog,proto3" json:"dest_log,omitempty"`
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

func (m *GoshawkConfig) GetDestLog() *LogConfig {
	if m != nil {
		return m.DestLog
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
	// 384 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x90, 0x41, 0x6e, 0xd4, 0x30,
	0x14, 0x86, 0xe5, 0x4e, 0x0b, 0x93, 0x97, 0x82, 0x8a, 0x61, 0x91, 0x16, 0x09, 0xa2, 0x59, 0x65,
	0xe5, 0xa0, 0x41, 0x3d, 0x00, 0x1a, 0xa4, 0x0a, 0xd1, 0x05, 0x32, 0x07, 0x88, 0x92, 0xf4, 0x25,
	0xb5, 0x26, 0xf1, 0x73, 0x1d, 0xa7, 0x28, 0x3d, 0x07, 0x87, 0xe0, 0x66, 0x5c, 0x03, 0xc5, 0xf1,
	0xb0, 0x00, 0xa1, 0x6e, 0x58, 0xe5, 0xf9, 0xfd, 0xff, 0x1f, 0xfd, 0xdf, 0x83, 0xd3, 0x9a, 0x74,
	0xa3, 0x5a, 0x61, 0x2c, 0x39, 0xe2, 0xeb, 0xe5, 0x65, 0xaa, 0x8b, 0xcb, 0x56, 0xb9, 0xdb, 0xb1,
	0x12, 0x35, 0xf5, 0x79, 0x4b, 0xd4, 0x76, 0x98, 0x3b, 0xab, 0xba, 0x4e, 0x95, 0x3a, 0xaf, 0xed,
	0x64, 0x1c, 0xe5, 0x7b, 0x9c, 0x06, 0x53, 0x85, 0xcf, 0xf2, 0x83, 0x8b, 0xf3, 0xe0, 0xf5, 0xaf,
	0x6a, 0x6c, 0xf2, 0x52, 0x4f, 0x41, 0x7a, 0xf3, 0xa7, 0x74, 0x33, 0xda, 0xd2, 0x29, 0xd2, 0x8b,
	0xbe, 0xf9, 0xc1, 0x20, 0xba, 0xa6, 0x76, 0xe7, 0x1b, 0x70, 0x0e, 0xc7, 0xba, 0xec, 0x31, 0x61,
	0x29, 0xcb, 0x22, 0xe9, 0x67, 0x7e, 0x06, 0xab, 0xd1, 0x76, 0xc9, 0x91, 0x5f, 0xcd, 0x23, 0x7f,
	0x07, 0x60, 0xc6, 0xaa, 0x53, 0x75, 0xb1, 0xc7, 0x29, 0x59, 0xa5, 0x2c, 0x8b, 0xb7, 0x2f, 0x44,
	0x68, 0xf4, 0xc5, 0x2b, 0x9f, 0x71, 0x92, 0x91, 0x39, 0x8c, 0x7c, 0x07, 0x67, 0xbd, 0xd2, 0x85,
	0xc5, 0xbb, 0x42, 0x69, 0x87, 0xf6, 0xbe, 0xec, 0x92, 0x63, 0x9f, 0x3b, 0x17, 0x4b, 0x41, 0x71,
	0x28, 0x28, 0x3e, 0x86, 0x82, 0xf2, 0x79, 0xaf, 0xb4, 0xc4, 0xbb, 0x4f, 0x21, 0xb0, 0xf9, 0xc9,
	0xe0, 0xf4, 0x8a, 0x86, 0x41, 0x99, 0xd0, 0x76, 0x0b, 0x30, 0xd0, 0x68, 0x6b, 0x2c, 0x3a, 0x6a,
	0x13, 0x96, 0xae, 0xb2, 0x78, 0xfb, 0x52, 0x1c, 0x8e, 0x29, 0x7e, 0x63, 0xc9, 0x68, 0xb1, 0x5d,
	0x53, 0xcb, 0x05, 0xac, 0x6f, 0x70, 0x70, 0x3e, 0x71, 0xf4, 0xef, 0xc4, 0xd3, 0xd9, 0x34, 0xfb,
	0x5f, 0x43, 0x64, 0x89, 0x5c, 0x51, 0xa3, 0x75, 0x1e, 0x35, 0x92, 0xeb, 0x79, 0xb1, 0x43, 0xeb,
	0xf8, 0x25, 0xc4, 0xc6, 0xaa, 0xfb, 0xd2, 0xa1, 0xbf, 0xc4, 0x42, 0xf4, 0xea, 0x2f, 0xa2, 0x0f,
	0x7a, 0x92, 0x10, 0x8c, 0xf3, 0x35, 0xde, 0x42, 0x5c, 0x8d, 0x4d, 0x83, 0xb6, 0x18, 0xd4, 0x03,
	0x26, 0x27, 0x29, 0xcb, 0x4e, 0x24, 0x2c, 0xab, 0xaf, 0xea, 0x01, 0x37, 0xdf, 0x19, 0x3c, 0xbb,
	0xa2, 0xe1, 0xb6, 0xfc, 0xb6, 0xff, 0x6f, 0xa8, 0xec, 0x51, 0xd4, 0xc7, 0x6a, 0x55, 0x4f, 0x3c,
	0xd1, 0xfb, 0x5f, 0x01, 0x00, 0x00, 0xff, 0xff, 0xce, 0xba, 0xf9, 0x5d, 0xbe, 0x02, 0x00, 0x00,
}
