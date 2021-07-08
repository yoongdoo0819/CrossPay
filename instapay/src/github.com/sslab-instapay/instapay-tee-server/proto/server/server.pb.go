// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        (unknown)
// source: server.proto

package server

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type PaymentRequestMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn     int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	From   string `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To     string `protobuf:"bytes,3,opt,name=to,proto3" json:"to,omitempty"`
	Amount int64  `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
}

func (x *PaymentRequestMessage) Reset() {
	*x = PaymentRequestMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PaymentRequestMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PaymentRequestMessage) ProtoMessage() {}

func (x *PaymentRequestMessage) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PaymentRequestMessage.ProtoReflect.Descriptor instead.
func (*PaymentRequestMessage) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{0}
}

func (x *PaymentRequestMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *PaymentRequestMessage) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *PaymentRequestMessage) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *PaymentRequestMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

type Address struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr string `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (x *Address) Reset() {
	*x = Address{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Address) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Address) ProtoMessage() {}

func (x *Address) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Address.ProtoReflect.Descriptor instead.
func (*Address) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{1}
}

func (x *Address) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

type Result struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result bool `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *Result) Reset() {
	*x = Result{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Result) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Result) ProtoMessage() {}

func (x *Result) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Result.ProtoReflect.Descriptor instead.
func (*Result) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{2}
}

func (x *Result) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

type CommunicationInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPAddress string `protobuf:"bytes,1,opt,name=IPAddress,json=iPAddress,proto3" json:"IPAddress,omitempty"`
	Port      int64  `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
}

func (x *CommunicationInfo) Reset() {
	*x = CommunicationInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommunicationInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommunicationInfo) ProtoMessage() {}

func (x *CommunicationInfo) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommunicationInfo.ProtoReflect.Descriptor instead.
func (*CommunicationInfo) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{3}
}

func (x *CommunicationInfo) GetIPAddress() string {
	if x != nil {
		return x.IPAddress
	}
	return ""
}

func (x *CommunicationInfo) GetPort() int64 {
	if x != nil {
		return x.Port
	}
	return 0
}

type CrossPaymentPrepareReqMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	From            string `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To              string `protobuf:"bytes,3,opt,name=to,proto3" json:"to,omitempty"`
	Amount          int64  `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,5,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,6,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentPrepareReqMessage) Reset() {
	*x = CrossPaymentPrepareReqMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentPrepareReqMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentPrepareReqMessage) ProtoMessage() {}

func (x *CrossPaymentPrepareReqMessage) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentPrepareReqMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentPrepareReqMessage) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{4}
}

func (x *CrossPaymentPrepareReqMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentPrepareReqMessage) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *CrossPaymentPrepareReqMessage) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *CrossPaymentPrepareReqMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *CrossPaymentPrepareReqMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentPrepareReqMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentCommitReqMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	From            string `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To              string `protobuf:"bytes,3,opt,name=to,proto3" json:"to,omitempty"`
	Amount          int64  `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,5,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,6,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentCommitReqMessage) Reset() {
	*x = CrossPaymentCommitReqMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentCommitReqMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentCommitReqMessage) ProtoMessage() {}

func (x *CrossPaymentCommitReqMessage) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentCommitReqMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentCommitReqMessage) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{5}
}

func (x *CrossPaymentCommitReqMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentCommitReqMessage) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *CrossPaymentCommitReqMessage) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *CrossPaymentCommitReqMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *CrossPaymentCommitReqMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentCommitReqMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentConfirmReqMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	From            string `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To              string `protobuf:"bytes,3,opt,name=to,proto3" json:"to,omitempty"`
	Amount          int64  `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,5,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,6,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentConfirmReqMessage) Reset() {
	*x = CrossPaymentConfirmReqMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentConfirmReqMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentConfirmReqMessage) ProtoMessage() {}

func (x *CrossPaymentConfirmReqMessage) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentConfirmReqMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentConfirmReqMessage) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{6}
}

func (x *CrossPaymentConfirmReqMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentConfirmReqMessage) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *CrossPaymentConfirmReqMessage) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *CrossPaymentConfirmReqMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *CrossPaymentConfirmReqMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentConfirmReqMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentRefundReqMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	From            string `protobuf:"bytes,2,opt,name=from,proto3" json:"from,omitempty"`
	To              string `protobuf:"bytes,3,opt,name=to,proto3" json:"to,omitempty"`
	Amount          int64  `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,5,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,6,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentRefundReqMessage) Reset() {
	*x = CrossPaymentRefundReqMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentRefundReqMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentRefundReqMessage) ProtoMessage() {}

func (x *CrossPaymentRefundReqMessage) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentRefundReqMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentRefundReqMessage) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{7}
}

func (x *CrossPaymentRefundReqMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentRefundReqMessage) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *CrossPaymentRefundReqMessage) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *CrossPaymentRefundReqMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *CrossPaymentRefundReqMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentRefundReqMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentPrepareResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	Result          bool   `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentPrepareResult) Reset() {
	*x = CrossPaymentPrepareResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentPrepareResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentPrepareResult) ProtoMessage() {}

func (x *CrossPaymentPrepareResult) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentPrepareResult.ProtoReflect.Descriptor instead.
func (*CrossPaymentPrepareResult) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{8}
}

func (x *CrossPaymentPrepareResult) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentPrepareResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *CrossPaymentPrepareResult) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentPrepareResult) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentCommitResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	Result          bool   `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentCommitResult) Reset() {
	*x = CrossPaymentCommitResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentCommitResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentCommitResult) ProtoMessage() {}

func (x *CrossPaymentCommitResult) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentCommitResult.ProtoReflect.Descriptor instead.
func (*CrossPaymentCommitResult) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{9}
}

func (x *CrossPaymentCommitResult) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentCommitResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *CrossPaymentCommitResult) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentCommitResult) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type CrossPaymentConfirmResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn              int64  `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	Result          bool   `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *CrossPaymentConfirmResult) Reset() {
	*x = CrossPaymentConfirmResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_server_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentConfirmResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentConfirmResult) ProtoMessage() {}

func (x *CrossPaymentConfirmResult) ProtoReflect() protoreflect.Message {
	mi := &file_server_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentConfirmResult.ProtoReflect.Descriptor instead.
func (*CrossPaymentConfirmResult) Descriptor() ([]byte, []int) {
	return file_server_proto_rawDescGZIP(), []int{10}
}

func (x *CrossPaymentConfirmResult) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentConfirmResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *CrossPaymentConfirmResult) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *CrossPaymentConfirmResult) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_server_proto protoreflect.FileDescriptor

var file_server_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x63,
	0x0a, 0x15, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74,
	0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x16, 0x0a, 0x06, 0x61,
	0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f,
	0x75, 0x6e, 0x74, 0x22, 0x1d, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x61, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64,
	0x64, 0x72, 0x22, 0x20, 0x0a, 0x06, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x16, 0x0a, 0x06,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x22, 0x45, 0x0a, 0x11, 0x43, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1c, 0x0a, 0x09, 0x49, 0x50, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x69, 0x50,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x22, 0xb3, 0x01, 0x0a, 0x1d,
	0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70,
	0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x12, 0x0a,
	0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f,
	0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74,
	0x6f, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0xb2, 0x01, 0x0a, 0x1c, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02,
	0x70, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x28,
	0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61,
	0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xb3, 0x01, 0x0a, 0x1d, 0x63, 0x72, 0x6f, 0x73, 0x73,
	0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52, 0x65,
	0x71, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02,
	0x74, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x16, 0x0a, 0x06,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x61, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f,
	0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xb2, 0x01, 0x0a,
	0x1c, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x66,
	0x75, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x12, 0x0a,
	0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f,
	0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74,
	0x6f, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0x8b, 0x01, 0x0a, 0x19, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12,
	0x0e, 0x0a, 0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12,
	0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69,
	0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22,
	0x8a, 0x01, 0x0a, 0x18, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x16, 0x0a, 0x06,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f,
	0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x8b, 0x01, 0x0a,
	0x19, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x72, 0x6d, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x32, 0xd1, 0x03, 0x0a, 0x06, 0x53,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x33, 0x0a, 0x0e, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x2e, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a,
	0x07, 0x2e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x3a, 0x0a, 0x18, 0x63, 0x6f,
	0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x08, 0x2e, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x1a, 0x12, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x49, 0x6e, 0x66, 0x6f, 0x22, 0x00, 0x12, 0x5a, 0x0a, 0x1a, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1e, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x1a, 0x1a, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x22, 0x00, 0x12, 0x57, 0x0a, 0x19, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1d, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x19,
	0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x5a, 0x0a, 0x1a, 0x63,
	0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x72, 0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e, 0x2e, 0x63, 0x72, 0x6f, 0x73,
	0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52,
	0x65, 0x71, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x1a, 0x2e, 0x63, 0x72, 0x6f, 0x73,
	0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x45, 0x0a, 0x19, 0x63, 0x72, 0x6f, 0x73, 0x73,
	0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x66, 0x75, 0x6e, 0x64, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x52, 0x65, 0x66, 0x75, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x1a, 0x07, 0x2e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_server_proto_rawDescOnce sync.Once
	file_server_proto_rawDescData = file_server_proto_rawDesc
)

func file_server_proto_rawDescGZIP() []byte {
	file_server_proto_rawDescOnce.Do(func() {
		file_server_proto_rawDescData = protoimpl.X.CompressGZIP(file_server_proto_rawDescData)
	})
	return file_server_proto_rawDescData
}

var file_server_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_server_proto_goTypes = []interface{}{
	(*PaymentRequestMessage)(nil),         // 0: paymentRequestMessage
	(*Address)(nil),                       // 1: address
	(*Result)(nil),                        // 2: Result
	(*CommunicationInfo)(nil),             // 3: CommunicationInfo
	(*CrossPaymentPrepareReqMessage)(nil), // 4: crossPaymentPrepareReqMessage
	(*CrossPaymentCommitReqMessage)(nil),  // 5: crossPaymentCommitReqMessage
	(*CrossPaymentConfirmReqMessage)(nil), // 6: crossPaymentConfirmReqMessage
	(*CrossPaymentRefundReqMessage)(nil),  // 7: crossPaymentRefundReqMessage
	(*CrossPaymentPrepareResult)(nil),     // 8: crossPaymentPrepareResult
	(*CrossPaymentCommitResult)(nil),      // 9: crossPaymentCommitResult
	(*CrossPaymentConfirmResult)(nil),     // 10: crossPaymentConfirmResult
}
var file_server_proto_depIdxs = []int32{
	0,  // 0: Server.paymentRequest:input_type -> paymentRequestMessage
	1,  // 1: Server.communicationInfoRequest:input_type -> address
	4,  // 2: Server.crossPaymentPrepareRequest:input_type -> crossPaymentPrepareReqMessage
	5,  // 3: Server.crossPaymentCommitRequest:input_type -> crossPaymentCommitReqMessage
	6,  // 4: Server.crossPaymentConfirmRequest:input_type -> crossPaymentConfirmReqMessage
	7,  // 5: Server.crossPaymentRefundRequest:input_type -> crossPaymentRefundReqMessage
	2,  // 6: Server.paymentRequest:output_type -> Result
	3,  // 7: Server.communicationInfoRequest:output_type -> CommunicationInfo
	8,  // 8: Server.crossPaymentPrepareRequest:output_type -> crossPaymentPrepareResult
	9,  // 9: Server.crossPaymentCommitRequest:output_type -> crossPaymentCommitResult
	10, // 10: Server.crossPaymentConfirmRequest:output_type -> crossPaymentConfirmResult
	2,  // 11: Server.crossPaymentRefundRequest:output_type -> Result
	6,  // [6:12] is the sub-list for method output_type
	0,  // [0:6] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_server_proto_init() }
func file_server_proto_init() {
	if File_server_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_server_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PaymentRequestMessage); i {
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
		file_server_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Address); i {
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
		file_server_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Result); i {
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
		file_server_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommunicationInfo); i {
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
		file_server_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentPrepareReqMessage); i {
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
		file_server_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentCommitReqMessage); i {
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
		file_server_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentConfirmReqMessage); i {
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
		file_server_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentRefundReqMessage); i {
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
		file_server_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentPrepareResult); i {
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
		file_server_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentCommitResult); i {
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
		file_server_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentConfirmResult); i {
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
			RawDescriptor: file_server_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_server_proto_goTypes,
		DependencyIndexes: file_server_proto_depIdxs,
		MessageInfos:      file_server_proto_msgTypes,
	}.Build()
	File_server_proto = out.File
	file_server_proto_rawDesc = nil
	file_server_proto_goTypes = nil
	file_server_proto_depIdxs = nil
}
