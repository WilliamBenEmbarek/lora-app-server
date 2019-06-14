// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protobuf/client_transaction_pb2/client_transaction.proto

package client_transaction_pb2

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
	client_list_control_pb2 "github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/client_list_control_pb2"
	transaction_pb2 "github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/transaction_pb2"
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

type ClientTransactionListResponse_Status int32

const (
	ClientTransactionListResponse_STATUS_UNSET   ClientTransactionListResponse_Status = 0
	ClientTransactionListResponse_OK             ClientTransactionListResponse_Status = 1
	ClientTransactionListResponse_INTERNAL_ERROR ClientTransactionListResponse_Status = 2
	ClientTransactionListResponse_NOT_READY      ClientTransactionListResponse_Status = 3
	ClientTransactionListResponse_NO_ROOT        ClientTransactionListResponse_Status = 4
	ClientTransactionListResponse_NO_RESOURCE    ClientTransactionListResponse_Status = 5
	ClientTransactionListResponse_INVALID_PAGING ClientTransactionListResponse_Status = 6
	ClientTransactionListResponse_INVALID_SORT   ClientTransactionListResponse_Status = 7
	ClientTransactionListResponse_INVALID_ID     ClientTransactionListResponse_Status = 8
)

var ClientTransactionListResponse_Status_name = map[int32]string{
	0: "STATUS_UNSET",
	1: "OK",
	2: "INTERNAL_ERROR",
	3: "NOT_READY",
	4: "NO_ROOT",
	5: "NO_RESOURCE",
	6: "INVALID_PAGING",
	7: "INVALID_SORT",
	8: "INVALID_ID",
}

var ClientTransactionListResponse_Status_value = map[string]int32{
	"STATUS_UNSET":   0,
	"OK":             1,
	"INTERNAL_ERROR": 2,
	"NOT_READY":      3,
	"NO_ROOT":        4,
	"NO_RESOURCE":    5,
	"INVALID_PAGING": 6,
	"INVALID_SORT":   7,
	"INVALID_ID":     8,
}

func (x ClientTransactionListResponse_Status) String() string {
	return proto.EnumName(ClientTransactionListResponse_Status_name, int32(x))
}

func (ClientTransactionListResponse_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{1, 0}
}

type ClientTransactionGetResponse_Status int32

const (
	ClientTransactionGetResponse_STATUS_UNSET   ClientTransactionGetResponse_Status = 0
	ClientTransactionGetResponse_OK             ClientTransactionGetResponse_Status = 1
	ClientTransactionGetResponse_INTERNAL_ERROR ClientTransactionGetResponse_Status = 2
	ClientTransactionGetResponse_NO_RESOURCE    ClientTransactionGetResponse_Status = 5
	ClientTransactionGetResponse_INVALID_ID     ClientTransactionGetResponse_Status = 8
)

var ClientTransactionGetResponse_Status_name = map[int32]string{
	0: "STATUS_UNSET",
	1: "OK",
	2: "INTERNAL_ERROR",
	5: "NO_RESOURCE",
	8: "INVALID_ID",
}

var ClientTransactionGetResponse_Status_value = map[string]int32{
	"STATUS_UNSET":   0,
	"OK":             1,
	"INTERNAL_ERROR": 2,
	"NO_RESOURCE":    5,
	"INVALID_ID":     8,
}

func (x ClientTransactionGetResponse_Status) String() string {
	return proto.EnumName(ClientTransactionGetResponse_Status_name, int32(x))
}

func (ClientTransactionGetResponse_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{3, 0}
}

// A request to return a list of txns from the validator. May include the id
// of a particular block to be the `head` of the chain being requested. In that
// case the list will include the txns from that block, and all txns
// previous to that block on the chain. Filter with specific `transaction_ids`.
type ClientTransactionListRequest struct {
	HeadId               string                                        `protobuf:"bytes,1,opt,name=head_id,json=headId,proto3" json:"head_id,omitempty"`
	TransactionIds       []string                                      `protobuf:"bytes,2,rep,name=transaction_ids,json=transactionIds,proto3" json:"transaction_ids,omitempty"`
	Paging               *client_list_control_pb2.ClientPagingControls `protobuf:"bytes,3,opt,name=paging,proto3" json:"paging,omitempty"`
	Sorting              []*client_list_control_pb2.ClientSortControls `protobuf:"bytes,4,rep,name=sorting,proto3" json:"sorting,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                      `json:"-"`
	XXX_unrecognized     []byte                                        `json:"-"`
	XXX_sizecache        int32                                         `json:"-"`
}

func (m *ClientTransactionListRequest) Reset()         { *m = ClientTransactionListRequest{} }
func (m *ClientTransactionListRequest) String() string { return proto.CompactTextString(m) }
func (*ClientTransactionListRequest) ProtoMessage()    {}
func (*ClientTransactionListRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{0}
}

func (m *ClientTransactionListRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientTransactionListRequest.Unmarshal(m, b)
}
func (m *ClientTransactionListRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientTransactionListRequest.Marshal(b, m, deterministic)
}
func (m *ClientTransactionListRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientTransactionListRequest.Merge(m, src)
}
func (m *ClientTransactionListRequest) XXX_Size() int {
	return xxx_messageInfo_ClientTransactionListRequest.Size(m)
}
func (m *ClientTransactionListRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientTransactionListRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ClientTransactionListRequest proto.InternalMessageInfo

func (m *ClientTransactionListRequest) GetHeadId() string {
	if m != nil {
		return m.HeadId
	}
	return ""
}

func (m *ClientTransactionListRequest) GetTransactionIds() []string {
	if m != nil {
		return m.TransactionIds
	}
	return nil
}

func (m *ClientTransactionListRequest) GetPaging() *client_list_control_pb2.ClientPagingControls {
	if m != nil {
		return m.Paging
	}
	return nil
}

func (m *ClientTransactionListRequest) GetSorting() []*client_list_control_pb2.ClientSortControls {
	if m != nil {
		return m.Sorting
	}
	return nil
}

// A response that lists transactions from newest to oldest.
//
// Statuses:
//   * OK - everything worked as expected
//   * INTERNAL_ERROR - general error, such as protobuf failing to deserialize
//   * NOT_READY - the validator does not yet have a genesis block
//   * NO_ROOT - the head block specified was not found
//   * NO_RESOURCE - no txns were found with the parameters specified
//   * INVALID_PAGING - the paging controls were malformed or out of range
//   * INVALID_SORT - the sorting controls were malformed or invalid
type ClientTransactionListResponse struct {
	Status               ClientTransactionListResponse_Status          `protobuf:"varint,1,opt,name=status,proto3,enum=ClientTransactionListResponse_Status" json:"status,omitempty"`
	Transactions         []*transaction_pb2.Transaction                `protobuf:"bytes,2,rep,name=transactions,proto3" json:"transactions,omitempty"`
	HeadId               string                                        `protobuf:"bytes,3,opt,name=head_id,json=headId,proto3" json:"head_id,omitempty"`
	Paging               *client_list_control_pb2.ClientPagingResponse `protobuf:"bytes,4,opt,name=paging,proto3" json:"paging,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                      `json:"-"`
	XXX_unrecognized     []byte                                        `json:"-"`
	XXX_sizecache        int32                                         `json:"-"`
}

func (m *ClientTransactionListResponse) Reset()         { *m = ClientTransactionListResponse{} }
func (m *ClientTransactionListResponse) String() string { return proto.CompactTextString(m) }
func (*ClientTransactionListResponse) ProtoMessage()    {}
func (*ClientTransactionListResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{1}
}

func (m *ClientTransactionListResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientTransactionListResponse.Unmarshal(m, b)
}
func (m *ClientTransactionListResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientTransactionListResponse.Marshal(b, m, deterministic)
}
func (m *ClientTransactionListResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientTransactionListResponse.Merge(m, src)
}
func (m *ClientTransactionListResponse) XXX_Size() int {
	return xxx_messageInfo_ClientTransactionListResponse.Size(m)
}
func (m *ClientTransactionListResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientTransactionListResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ClientTransactionListResponse proto.InternalMessageInfo

func (m *ClientTransactionListResponse) GetStatus() ClientTransactionListResponse_Status {
	if m != nil {
		return m.Status
	}
	return ClientTransactionListResponse_STATUS_UNSET
}

func (m *ClientTransactionListResponse) GetTransactions() []*transaction_pb2.Transaction {
	if m != nil {
		return m.Transactions
	}
	return nil
}

func (m *ClientTransactionListResponse) GetHeadId() string {
	if m != nil {
		return m.HeadId
	}
	return ""
}

func (m *ClientTransactionListResponse) GetPaging() *client_list_control_pb2.ClientPagingResponse {
	if m != nil {
		return m.Paging
	}
	return nil
}

// Fetches a specific txn by its id (header_signature) from the blockchain.
type ClientTransactionGetRequest struct {
	TransactionId        string   `protobuf:"bytes,1,opt,name=transaction_id,json=transactionId,proto3" json:"transaction_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientTransactionGetRequest) Reset()         { *m = ClientTransactionGetRequest{} }
func (m *ClientTransactionGetRequest) String() string { return proto.CompactTextString(m) }
func (*ClientTransactionGetRequest) ProtoMessage()    {}
func (*ClientTransactionGetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{2}
}

func (m *ClientTransactionGetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientTransactionGetRequest.Unmarshal(m, b)
}
func (m *ClientTransactionGetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientTransactionGetRequest.Marshal(b, m, deterministic)
}
func (m *ClientTransactionGetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientTransactionGetRequest.Merge(m, src)
}
func (m *ClientTransactionGetRequest) XXX_Size() int {
	return xxx_messageInfo_ClientTransactionGetRequest.Size(m)
}
func (m *ClientTransactionGetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientTransactionGetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ClientTransactionGetRequest proto.InternalMessageInfo

func (m *ClientTransactionGetRequest) GetTransactionId() string {
	if m != nil {
		return m.TransactionId
	}
	return ""
}

// A response that returns the txn specified by a ClientTransactionGetRequest.
//
// Statuses:
//   * OK - everything worked as expected, txn has been fetched
//   * INTERNAL_ERROR - general error, such as protobuf failing to deserialize
//   * NO_RESOURCE - no txn with the specified id exists
type ClientTransactionGetResponse struct {
	Status               ClientTransactionGetResponse_Status `protobuf:"varint,1,opt,name=status,proto3,enum=ClientTransactionGetResponse_Status" json:"status,omitempty"`
	Transaction          *transaction_pb2.Transaction        `protobuf:"bytes,2,opt,name=transaction,proto3" json:"transaction,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *ClientTransactionGetResponse) Reset()         { *m = ClientTransactionGetResponse{} }
func (m *ClientTransactionGetResponse) String() string { return proto.CompactTextString(m) }
func (*ClientTransactionGetResponse) ProtoMessage()    {}
func (*ClientTransactionGetResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e4773396c2a1767, []int{3}
}

func (m *ClientTransactionGetResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientTransactionGetResponse.Unmarshal(m, b)
}
func (m *ClientTransactionGetResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientTransactionGetResponse.Marshal(b, m, deterministic)
}
func (m *ClientTransactionGetResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientTransactionGetResponse.Merge(m, src)
}
func (m *ClientTransactionGetResponse) XXX_Size() int {
	return xxx_messageInfo_ClientTransactionGetResponse.Size(m)
}
func (m *ClientTransactionGetResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientTransactionGetResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ClientTransactionGetResponse proto.InternalMessageInfo

func (m *ClientTransactionGetResponse) GetStatus() ClientTransactionGetResponse_Status {
	if m != nil {
		return m.Status
	}
	return ClientTransactionGetResponse_STATUS_UNSET
}

func (m *ClientTransactionGetResponse) GetTransaction() *transaction_pb2.Transaction {
	if m != nil {
		return m.Transaction
	}
	return nil
}

func init() {
	proto.RegisterEnum("ClientTransactionListResponse_Status", ClientTransactionListResponse_Status_name, ClientTransactionListResponse_Status_value)
	proto.RegisterEnum("ClientTransactionGetResponse_Status", ClientTransactionGetResponse_Status_name, ClientTransactionGetResponse_Status_value)
	proto.RegisterType((*ClientTransactionListRequest)(nil), "ClientTransactionListRequest")
	proto.RegisterType((*ClientTransactionListResponse)(nil), "ClientTransactionListResponse")
	proto.RegisterType((*ClientTransactionGetRequest)(nil), "ClientTransactionGetRequest")
	proto.RegisterType((*ClientTransactionGetResponse)(nil), "ClientTransactionGetResponse")
}

func init() {
	proto.RegisterFile("github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/client_transaction_pb2/client_transaction.proto", fileDescriptor_8e4773396c2a1767)
}

var fileDescriptor_8e4773396c2a1767 = []byte{
	// 496 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x94, 0xdd, 0x8e, 0x93, 0x40,
	0x14, 0xc7, 0x05, 0x2a, 0xb5, 0x87, 0x2e, 0x3b, 0x19, 0xb3, 0xda, 0xf8, 0x91, 0x34, 0xc4, 0x8d,
	0x8d, 0xc9, 0xa2, 0xe2, 0x8d, 0x31, 0x7a, 0x81, 0x2d, 0x69, 0x88, 0x0d, 0x34, 0x03, 0xd5, 0xe8,
	0x0d, 0xa1, 0x05, 0x77, 0x89, 0x0d, 0x53, 0x99, 0x69, 0x7c, 0x16, 0x5f, 0xc6, 0xb7, 0xf1, 0x0d,
	0x7c, 0x00, 0x53, 0x3e, 0xba, 0x40, 0xeb, 0x5e, 0x78, 0x39, 0xa7, 0xbf, 0xff, 0xf9, 0xf8, 0x9f,
	0x53, 0xe0, 0xf5, 0x26, 0xa3, 0x9c, 0x2e, 0xb7, 0x5f, 0x9f, 0xaf, 0xd6, 0x49, 0x9c, 0xf2, 0x80,
	0x67, 0x61, 0xca, 0xc2, 0x15, 0x4f, 0x68, 0x1a, 0x6c, 0x96, 0xc6, 0x91, 0xb0, 0x9e, 0x4b, 0x1e,
	0x3c, 0xdb, 0x2b, 0xdb, 0x92, 0x43, 0xf6, 0x4d, 0xbb, 0xca, 0x3a, 0x61, 0x3c, 0x58, 0xd1, 0x94,
	0x67, 0x74, 0x5d, 0x2f, 0x53, 0x8f, 0x17, 0x5a, 0xed, 0x97, 0x00, 0x8f, 0xc6, 0xf9, 0xaf, 0xfe,
	0x75, 0xde, 0x59, 0xc2, 0x38, 0x89, 0xbf, 0x6f, 0x63, 0xc6, 0xf1, 0x7d, 0xe8, 0x5e, 0xc5, 0x61,
	0x14, 0x24, 0xd1, 0x40, 0x18, 0x0a, 0xa3, 0x1e, 0x91, 0x77, 0x4f, 0x3b, 0xc2, 0x4f, 0xe1, 0xb4,
	0xde, 0x5a, 0x12, 0xb1, 0x81, 0x38, 0x94, 0x46, 0x3d, 0xa2, 0xd6, 0xc2, 0x76, 0xc4, 0xf0, 0x05,
	0xc8, 0x9b, 0xf0, 0x32, 0x49, 0x2f, 0x07, 0xd2, 0x50, 0x18, 0x29, 0xc6, 0x99, 0x5e, 0x14, 0x9c,
	0xe7, 0xc1, 0x71, 0xd1, 0x0e, 0x23, 0x25, 0x84, 0x2f, 0xa0, 0xcb, 0x68, 0xc6, 0x77, 0x7c, 0x67,
	0x28, 0x8d, 0x14, 0xe3, 0x6e, 0xc9, 0x7b, 0x34, 0xe3, 0x7b, 0xba, 0x62, 0xb4, 0x3f, 0x22, 0x3c,
	0xfe, 0xc7, 0x00, 0x6c, 0x43, 0x53, 0x16, 0xe3, 0x77, 0x20, 0x33, 0x1e, 0xf2, 0x2d, 0xcb, 0x07,
	0x50, 0x8d, 0x73, 0xfd, 0x46, 0x5e, 0xf7, 0x72, 0x98, 0x94, 0x22, 0xfc, 0x02, 0xfa, 0xb5, 0x81,
	0x8a, 0x21, 0x15, 0xa3, 0xaf, 0xd7, 0xe4, 0xa4, 0x41, 0xd4, 0x2d, 0x93, 0x1a, 0x96, 0x5d, 0x3b,
	0xd1, 0x39, 0xe2, 0x44, 0xd5, 0x40, 0xe5, 0x84, 0xf6, 0x53, 0x00, 0xb9, 0x68, 0x06, 0x23, 0xe8,
	0x7b, 0xbe, 0xe9, 0x2f, 0xbc, 0x60, 0xe1, 0x78, 0x96, 0x8f, 0x6e, 0x61, 0x19, 0x44, 0xf7, 0x03,
	0x12, 0x30, 0x06, 0xd5, 0x76, 0x7c, 0x8b, 0x38, 0xe6, 0x2c, 0xb0, 0x08, 0x71, 0x09, 0x12, 0xf1,
	0x09, 0xf4, 0x1c, 0xd7, 0x0f, 0x88, 0x65, 0x4e, 0x3e, 0x23, 0x09, 0x2b, 0xd0, 0x75, 0xdc, 0x80,
	0xb8, 0xae, 0x8f, 0x3a, 0xf8, 0x14, 0x94, 0xdd, 0xc3, 0xf2, 0xdc, 0x05, 0x19, 0x5b, 0xe8, 0x76,
	0x91, 0xe0, 0xa3, 0x39, 0xb3, 0x27, 0xc1, 0xdc, 0x9c, 0xda, 0xce, 0x14, 0xc9, 0xbb, 0x72, 0x55,
	0xcc, 0x73, 0x89, 0x8f, 0xba, 0x58, 0x05, 0xa8, 0x22, 0xf6, 0x04, 0xdd, 0xd1, 0x26, 0xf0, 0xf0,
	0xc0, 0xc5, 0x69, 0xbc, 0xbf, 0x9a, 0x73, 0x50, 0x9b, 0xc7, 0x51, 0x1e, 0xcf, 0x49, 0xe3, 0x36,
	0xb4, 0xdf, 0xc7, 0xae, 0x2f, 0x4f, 0x53, 0xee, 0xee, 0x6d, 0x6b, 0x77, 0x4f, 0xf4, 0x9b, 0xf0,
	0xf6, 0xea, 0x74, 0x50, 0x6a, 0xf5, 0x06, 0x62, 0x6e, 0x7a, 0x73, 0x73, 0x75, 0x40, 0xfb, 0xf4,
	0x9f, 0x7e, 0x1f, 0x78, 0xda, 0x72, 0xeb, 0xfd, 0x4b, 0x38, 0x63, 0xe1, 0x0f, 0x4e, 0x29, 0xbf,
	0xd2, 0x59, 0xf4, 0x4d, 0xaf, 0xfe, 0xb0, 0x73, 0xe1, 0xcb, 0xbd, 0xe3, 0x5f, 0x86, 0xa5, 0x9c,
	0x33, 0xaf, 0xfe, 0x06, 0x00, 0x00, 0xff, 0xff, 0xf1, 0xe4, 0x14, 0xba, 0x43, 0x04, 0x00, 0x00,
}