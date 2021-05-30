// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        (unknown)
// source: client.proto

package client

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

type AgreeRequestsMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber   int64            `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	ChannelPayments *ChannelPayments `protobuf:"bytes,2,opt,name=channelPayments,proto3" json:"channelPayments,omitempty"`
	OriginalMessage []byte           `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte           `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *AgreeRequestsMessage) Reset() {
	*x = AgreeRequestsMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AgreeRequestsMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgreeRequestsMessage) ProtoMessage() {}

func (x *AgreeRequestsMessage) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgreeRequestsMessage.ProtoReflect.Descriptor instead.
func (*AgreeRequestsMessage) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{0}
}

func (x *AgreeRequestsMessage) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *AgreeRequestsMessage) GetChannelPayments() *ChannelPayments {
	if x != nil {
		return x.ChannelPayments
	}
	return nil
}

func (x *AgreeRequestsMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *AgreeRequestsMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type UpdateRequestsMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber   int64            `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	ChannelPayments *ChannelPayments `protobuf:"bytes,2,opt,name=channelPayments,proto3" json:"channelPayments,omitempty"`
	OriginalMessage [][]byte         `protobuf:"bytes,3,rep,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       [][]byte         `protobuf:"bytes,4,rep,name=signature,proto3" json:"signature,omitempty"`
}

func (x *UpdateRequestsMessage) Reset() {
	*x = UpdateRequestsMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateRequestsMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRequestsMessage) ProtoMessage() {}

func (x *UpdateRequestsMessage) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRequestsMessage.ProtoReflect.Descriptor instead.
func (*UpdateRequestsMessage) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{1}
}

func (x *UpdateRequestsMessage) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *UpdateRequestsMessage) GetChannelPayments() *ChannelPayments {
	if x != nil {
		return x.ChannelPayments
	}
	return nil
}

func (x *UpdateRequestsMessage) GetOriginalMessage() [][]byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *UpdateRequestsMessage) GetSignature() [][]byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ConfirmRequestsMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber   int64    `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	OriginalMessage [][]byte `protobuf:"bytes,2,rep,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       [][]byte `protobuf:"bytes,3,rep,name=signature,proto3" json:"signature,omitempty"`
}

func (x *ConfirmRequestsMessage) Reset() {
	*x = ConfirmRequestsMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfirmRequestsMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfirmRequestsMessage) ProtoMessage() {}

func (x *ConfirmRequestsMessage) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfirmRequestsMessage.ProtoReflect.Descriptor instead.
func (*ConfirmRequestsMessage) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{2}
}

func (x *ConfirmRequestsMessage) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *ConfirmRequestsMessage) GetOriginalMessage() [][]byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *ConfirmRequestsMessage) GetSignature() [][]byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ChannelPayment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelId int64 `protobuf:"varint,1,opt,name=channelId,proto3" json:"channelId,omitempty"`
	Amount    int64 `protobuf:"varint,2,opt,name=amount,proto3" json:"amount,omitempty"`
}

func (x *ChannelPayment) Reset() {
	*x = ChannelPayment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannelPayment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannelPayment) ProtoMessage() {}

func (x *ChannelPayment) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannelPayment.ProtoReflect.Descriptor instead.
func (*ChannelPayment) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{3}
}

func (x *ChannelPayment) GetChannelId() int64 {
	if x != nil {
		return x.ChannelId
	}
	return 0
}

func (x *ChannelPayment) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

type DirectChannelPaymentMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelId       int64  `protobuf:"varint,1,opt,name=channelId,proto3" json:"channelId,omitempty"`
	Amount          int64  `protobuf:"varint,2,opt,name=amount,proto3" json:"amount,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *DirectChannelPaymentMessage) Reset() {
	*x = DirectChannelPaymentMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DirectChannelPaymentMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DirectChannelPaymentMessage) ProtoMessage() {}

func (x *DirectChannelPaymentMessage) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DirectChannelPaymentMessage.ProtoReflect.Descriptor instead.
func (*DirectChannelPaymentMessage) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{4}
}

func (x *DirectChannelPaymentMessage) GetChannelId() int64 {
	if x != nil {
		return x.ChannelId
	}
	return 0
}

func (x *DirectChannelPaymentMessage) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *DirectChannelPaymentMessage) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *DirectChannelPaymentMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ChannelPayments struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelPayments []*ChannelPayment `protobuf:"bytes,1,rep,name=channelPayments,proto3" json:"channelPayments,omitempty"`
}

func (x *ChannelPayments) Reset() {
	*x = ChannelPayments{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannelPayments) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannelPayments) ProtoMessage() {}

func (x *ChannelPayments) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannelPayments.ProtoReflect.Descriptor instead.
func (*ChannelPayments) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{5}
}

func (x *ChannelPayments) GetChannelPayments() []*ChannelPayment {
	if x != nil {
		return x.ChannelPayments
	}
	return nil
}

type AgreementResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber   int64  `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	Result          bool   `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *AgreementResult) Reset() {
	*x = AgreementResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AgreementResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgreementResult) ProtoMessage() {}

func (x *AgreementResult) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgreementResult.ProtoReflect.Descriptor instead.
func (*AgreementResult) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{6}
}

func (x *AgreementResult) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *AgreementResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *AgreementResult) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *AgreementResult) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type UpdateResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber   int64  `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	Result          bool   `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
	OriginalMessage []byte `protobuf:"bytes,3,opt,name=originalMessage,proto3" json:"originalMessage,omitempty"`
	Signature       []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *UpdateResult) Reset() {
	*x = UpdateResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateResult) ProtoMessage() {}

func (x *UpdateResult) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateResult.ProtoReflect.Descriptor instead.
func (*UpdateResult) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateResult) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *UpdateResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *UpdateResult) GetOriginalMessage() []byte {
	if x != nil {
		return x.OriginalMessage
	}
	return nil
}

func (x *UpdateResult) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ConfirmResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaymentNumber int64 `protobuf:"varint,1,opt,name=paymentNumber,proto3" json:"paymentNumber,omitempty"`
	Result        bool  `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *ConfirmResult) Reset() {
	*x = ConfirmResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfirmResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfirmResult) ProtoMessage() {}

func (x *ConfirmResult) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfirmResult.ProtoReflect.Descriptor instead.
func (*ConfirmResult) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{8}
}

func (x *ConfirmResult) GetPaymentNumber() int64 {
	if x != nil {
		return x.PaymentNumber
	}
	return 0
}

func (x *ConfirmResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

type DirectPaymentResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result         bool   `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
	ReplyMessage   []byte `protobuf:"bytes,2,opt,name=replyMessage,proto3" json:"replyMessage,omitempty"`
	ReplySignature []byte `protobuf:"bytes,3,opt,name=replySignature,proto3" json:"replySignature,omitempty"`
}

func (x *DirectPaymentResult) Reset() {
	*x = DirectPaymentResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_client_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DirectPaymentResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DirectPaymentResult) ProtoMessage() {}

func (x *DirectPaymentResult) ProtoReflect() protoreflect.Message {
	mi := &file_client_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DirectPaymentResult.ProtoReflect.Descriptor instead.
func (*DirectPaymentResult) Descriptor() ([]byte, []int) {
	return file_client_proto_rawDescGZIP(), []int{9}
}

func (x *DirectPaymentResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

func (x *DirectPaymentResult) GetReplyMessage() []byte {
	if x != nil {
		return x.ReplyMessage
	}
	return nil
}

func (x *DirectPaymentResult) GetReplySignature() []byte {
	if x != nil {
		return x.ReplySignature
	}
	return nil
}

var File_client_proto protoreflect.FileDescriptor

var file_client_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc0,
	0x01, 0x0a, 0x14, 0x41, 0x67, 0x72, 0x65, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d,
	0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x3a, 0x0a,
	0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c,
	0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0xc1, 0x01, 0x0a, 0x15, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x24, 0x0a, 0x0d, 0x70,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x12, 0x3a, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x43, 0x68, 0x61,
	0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x0f, 0x63, 0x68,
	0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x28, 0x0a,
	0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x86, 0x01, 0x0a, 0x16, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72,
	0x6d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x24, 0x0a, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e,
	0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x46,
	0x0a, 0x0e, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x12, 0x1c, 0x0a, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x9b, 0x01, 0x0a, 0x1b, 0x44, 0x69, 0x72, 0x65, 0x63,
	0x74, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x49, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x0f,
	0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x22, 0x4c, 0x0a, 0x0f, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x39, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x52, 0x0f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x73, 0x22, 0x97, 0x01, 0x0a, 0x0f, 0x41, 0x67, 0x72, 0x65, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f,
	0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x94, 0x01, 0x0a,
	0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x24, 0x0a,
	0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x6f,
	0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x22, 0x4d, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x22, 0x79, 0x0a, 0x13, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73,
	0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x12, 0x22, 0x0a, 0x0c, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x26, 0x0a, 0x0e, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x72,
	0x65, 0x70, 0x6c, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x32, 0x8c, 0x02,
	0x0a, 0x06, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x3d, 0x0a, 0x10, 0x61, 0x67, 0x72, 0x65,
	0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15, 0x2e, 0x41,
	0x67, 0x72, 0x65, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x1a, 0x10, 0x2e, 0x41, 0x67, 0x72, 0x65, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x38, 0x0a, 0x0d, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x1a, 0x0d, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22,
	0x00, 0x12, 0x3b, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x50, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x17, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x0e, 0x2e, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x4c,
	0x0a, 0x14, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x1c, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43,
	0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x1a, 0x14, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x50, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_client_proto_rawDescOnce sync.Once
	file_client_proto_rawDescData = file_client_proto_rawDesc
)

func file_client_proto_rawDescGZIP() []byte {
	file_client_proto_rawDescOnce.Do(func() {
		file_client_proto_rawDescData = protoimpl.X.CompressGZIP(file_client_proto_rawDescData)
	})
	return file_client_proto_rawDescData
}

var file_client_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_client_proto_goTypes = []interface{}{
	(*AgreeRequestsMessage)(nil),        // 0: AgreeRequestsMessage
	(*UpdateRequestsMessage)(nil),       // 1: UpdateRequestsMessage
	(*ConfirmRequestsMessage)(nil),      // 2: ConfirmRequestsMessage
	(*ChannelPayment)(nil),              // 3: ChannelPayment
	(*DirectChannelPaymentMessage)(nil), // 4: DirectChannelPaymentMessage
	(*ChannelPayments)(nil),             // 5: ChannelPayments
	(*AgreementResult)(nil),             // 6: AgreementResult
	(*UpdateResult)(nil),                // 7: UpdateResult
	(*ConfirmResult)(nil),               // 8: ConfirmResult
	(*DirectPaymentResult)(nil),         // 9: DirectPaymentResult
}
var file_client_proto_depIdxs = []int32{
	5, // 0: AgreeRequestsMessage.channelPayments:type_name -> ChannelPayments
	5, // 1: UpdateRequestsMessage.channelPayments:type_name -> ChannelPayments
	3, // 2: ChannelPayments.channelPayments:type_name -> ChannelPayment
	0, // 3: Client.agreementRequest:input_type -> AgreeRequestsMessage
	1, // 4: Client.updateRequest:input_type -> UpdateRequestsMessage
	2, // 5: Client.confirmPayment:input_type -> ConfirmRequestsMessage
	4, // 6: Client.directChannelPayment:input_type -> DirectChannelPaymentMessage
	6, // 7: Client.agreementRequest:output_type -> AgreementResult
	7, // 8: Client.updateRequest:output_type -> UpdateResult
	8, // 9: Client.confirmPayment:output_type -> ConfirmResult
	9, // 10: Client.directChannelPayment:output_type -> DirectPaymentResult
	7, // [7:11] is the sub-list for method output_type
	3, // [3:7] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_client_proto_init() }
func file_client_proto_init() {
	if File_client_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_client_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AgreeRequestsMessage); i {
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
		file_client_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateRequestsMessage); i {
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
		file_client_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfirmRequestsMessage); i {
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
		file_client_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannelPayment); i {
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
		file_client_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DirectChannelPaymentMessage); i {
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
		file_client_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannelPayments); i {
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
		file_client_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AgreementResult); i {
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
		file_client_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateResult); i {
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
		file_client_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfirmResult); i {
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
		file_client_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DirectPaymentResult); i {
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
			RawDescriptor: file_client_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_client_proto_goTypes,
		DependencyIndexes: file_client_proto_depIdxs,
		MessageInfos:      file_client_proto_msgTypes,
	}.Build()
	File_client_proto = out.File
	file_client_proto_rawDesc = nil
	file_client_proto_goTypes = nil
	file_client_proto_depIdxs = nil
}
