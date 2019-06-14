// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protobuf/client_status_pb2/client_status.proto

package client_status

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// The status of the response message, not the validator's status
type ClientStatusGetResponse_Status int32

const (
	ClientStatusGetResponse_STATUS_UNSET ClientStatusGetResponse_Status = 0
	ClientStatusGetResponse_OK           ClientStatusGetResponse_Status = 1
	ClientStatusGetResponse_ERROR        ClientStatusGetResponse_Status = 2
)

var ClientStatusGetResponse_Status_name = map[int32]string{
	0: "STATUS_UNSET",
	1: "OK",
	2: "ERROR",
}

var ClientStatusGetResponse_Status_value = map[string]int32{
	"STATUS_UNSET": 0,
	"OK":           1,
	"ERROR":        2,
}

func (x ClientStatusGetResponse_Status) String() string {
	return proto.EnumName(ClientStatusGetResponse_Status_name, int32(x))
}

func (ClientStatusGetResponse_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_a42ba723655895b0, []int{1, 0}
}

// A request to get miscellaneous information about the validator
type ClientStatusGetRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientStatusGetRequest) Reset()         { *m = ClientStatusGetRequest{} }
func (m *ClientStatusGetRequest) String() string { return proto.CompactTextString(m) }
func (*ClientStatusGetRequest) ProtoMessage()    {}
func (*ClientStatusGetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a42ba723655895b0, []int{0}
}

func (m *ClientStatusGetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientStatusGetRequest.Unmarshal(m, b)
}
func (m *ClientStatusGetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientStatusGetRequest.Marshal(b, m, deterministic)
}
func (m *ClientStatusGetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientStatusGetRequest.Merge(m, src)
}
func (m *ClientStatusGetRequest) XXX_Size() int {
	return xxx_messageInfo_ClientStatusGetRequest.Size(m)
}
func (m *ClientStatusGetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientStatusGetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ClientStatusGetRequest proto.InternalMessageInfo

type ClientStatusGetResponse struct {
	Status ClientStatusGetResponse_Status  `protobuf:"varint,1,opt,name=status,proto3,enum=ClientStatusGetResponse_Status" json:"status,omitempty"`
	Peers  []*ClientStatusGetResponse_Peer `protobuf:"bytes,2,rep,name=peers,proto3" json:"peers,omitempty"`
	// The validator's public network endpoint
	Endpoint             string   `protobuf:"bytes,3,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientStatusGetResponse) Reset()         { *m = ClientStatusGetResponse{} }
func (m *ClientStatusGetResponse) String() string { return proto.CompactTextString(m) }
func (*ClientStatusGetResponse) ProtoMessage()    {}
func (*ClientStatusGetResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a42ba723655895b0, []int{1}
}

func (m *ClientStatusGetResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientStatusGetResponse.Unmarshal(m, b)
}
func (m *ClientStatusGetResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientStatusGetResponse.Marshal(b, m, deterministic)
}
func (m *ClientStatusGetResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientStatusGetResponse.Merge(m, src)
}
func (m *ClientStatusGetResponse) XXX_Size() int {
	return xxx_messageInfo_ClientStatusGetResponse.Size(m)
}
func (m *ClientStatusGetResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientStatusGetResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ClientStatusGetResponse proto.InternalMessageInfo

func (m *ClientStatusGetResponse) GetStatus() ClientStatusGetResponse_Status {
	if m != nil {
		return m.Status
	}
	return ClientStatusGetResponse_STATUS_UNSET
}

func (m *ClientStatusGetResponse) GetPeers() []*ClientStatusGetResponse_Peer {
	if m != nil {
		return m.Peers
	}
	return nil
}

func (m *ClientStatusGetResponse) GetEndpoint() string {
	if m != nil {
		return m.Endpoint
	}
	return ""
}

// Information about the validator's peers
type ClientStatusGetResponse_Peer struct {
	// The peer's public network endpoint
	Endpoint             string   `protobuf:"bytes,1,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientStatusGetResponse_Peer) Reset()         { *m = ClientStatusGetResponse_Peer{} }
func (m *ClientStatusGetResponse_Peer) String() string { return proto.CompactTextString(m) }
func (*ClientStatusGetResponse_Peer) ProtoMessage()    {}
func (*ClientStatusGetResponse_Peer) Descriptor() ([]byte, []int) {
	return fileDescriptor_a42ba723655895b0, []int{1, 0}
}

func (m *ClientStatusGetResponse_Peer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientStatusGetResponse_Peer.Unmarshal(m, b)
}
func (m *ClientStatusGetResponse_Peer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientStatusGetResponse_Peer.Marshal(b, m, deterministic)
}
func (m *ClientStatusGetResponse_Peer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientStatusGetResponse_Peer.Merge(m, src)
}
func (m *ClientStatusGetResponse_Peer) XXX_Size() int {
	return xxx_messageInfo_ClientStatusGetResponse_Peer.Size(m)
}
func (m *ClientStatusGetResponse_Peer) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientStatusGetResponse_Peer.DiscardUnknown(m)
}

var xxx_messageInfo_ClientStatusGetResponse_Peer proto.InternalMessageInfo

func (m *ClientStatusGetResponse_Peer) GetEndpoint() string {
	if m != nil {
		return m.Endpoint
	}
	return ""
}

func init() {
	proto.RegisterEnum("ClientStatusGetResponse_Status", ClientStatusGetResponse_Status_name, ClientStatusGetResponse_Status_value)
	proto.RegisterType((*ClientStatusGetRequest)(nil), "ClientStatusGetRequest")
	proto.RegisterType((*ClientStatusGetResponse)(nil), "ClientStatusGetResponse")
	proto.RegisterType((*ClientStatusGetResponse_Peer)(nil), "ClientStatusGetResponse.Peer")
}

func init() {
	proto.RegisterFile("github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/client_status_pb2/client_status.proto", fileDescriptor_a42ba723655895b0)
}

var fileDescriptor_a42ba723655895b0 = []byte{
	// 242 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0xcf, 0x4b, 0xc3, 0x40,
	0x10, 0x85, 0xdd, 0xd4, 0x06, 0x3b, 0xfe, 0x20, 0x2c, 0xa8, 0xa1, 0x20, 0x86, 0x9c, 0x72, 0x31,
	0x42, 0x7a, 0xf0, 0xac, 0x52, 0x3c, 0x08, 0xb6, 0x6c, 0xd2, 0x8b, 0x97, 0xd0, 0xd8, 0x11, 0x8b,
	0xb2, 0xbb, 0x66, 0x26, 0xf8, 0x9f, 0x7b, 0x16, 0xb3, 0x52, 0x58, 0x24, 0xc7, 0xf9, 0xde, 0x37,
	0x33, 0xf0, 0x20, 0xb7, 0xad, 0x61, 0xd3, 0x74, 0xaf, 0xd7, 0x2f, 0x1f, 0x5b, 0xd4, 0x5c, 0x13,
	0xaf, 0xb9, 0xa3, 0xda, 0x36, 0x85, 0x4f, 0x9c, 0x98, 0xc6, 0x70, 0x76, 0xdf, 0xe3, 0xb2, 0xa7,
	0x0f, 0xc8, 0x0a, 0x3f, 0x3b, 0x24, 0x4e, 0xbf, 0x05, 0x9c, 0xff, 0x8b, 0xc8, 0x1a, 0x4d, 0x28,
	0x6f, 0x20, 0x74, 0x57, 0x62, 0x91, 0x88, 0xec, 0xa4, 0xb8, 0xcc, 0x07, 0xcc, 0xdc, 0x11, 0xf5,
	0xa7, 0xcb, 0x19, 0x8c, 0x2d, 0x62, 0x4b, 0x71, 0x90, 0x8c, 0xb2, 0xc3, 0xe2, 0x62, 0x70, 0x6f,
	0x89, 0xd8, 0x2a, 0xe7, 0xca, 0x29, 0x1c, 0xa0, 0xde, 0x58, 0xb3, 0xd5, 0x1c, 0x8f, 0x12, 0x91,
	0x4d, 0xd4, 0x6e, 0x9e, 0xa6, 0xb0, 0xff, 0xab, 0x7a, 0x8e, 0xf0, 0x9d, 0xf4, 0x0a, 0x42, 0xf7,
	0x40, 0x46, 0x70, 0x54, 0x56, 0xb7, 0xd5, 0xaa, 0xac, 0x57, 0x4f, 0xe5, 0xbc, 0x8a, 0xf6, 0x64,
	0x08, 0xc1, 0xe2, 0x31, 0x12, 0x72, 0x02, 0xe3, 0xb9, 0x52, 0x0b, 0x15, 0x05, 0x77, 0x19, 0x9c,
	0xd2, 0xfa, 0x8b, 0x8d, 0xe1, 0xb7, 0x9c, 0x36, 0xef, 0xbb, 0x46, 0x97, 0xe2, 0xf9, 0xd8, 0xab,
	0xb0, 0x09, 0xfb, 0x68, 0xf6, 0x13, 0x00, 0x00, 0xff, 0xff, 0xc4, 0xe2, 0x52, 0x83, 0x75, 0x01,
	0x00, 0x00,
}