// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        (unknown)
// source: cross_server.proto

package cross_server

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

type CrossPaymentPrepareResMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn     int64 `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	Result bool  `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CrossPaymentPrepareResMessage) Reset() {
	*x = CrossPaymentPrepareResMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cross_server_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentPrepareResMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentPrepareResMessage) ProtoMessage() {}

func (x *CrossPaymentPrepareResMessage) ProtoReflect() protoreflect.Message {
	mi := &file_cross_server_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentPrepareResMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentPrepareResMessage) Descriptor() ([]byte, []int) {
	return file_cross_server_proto_rawDescGZIP(), []int{0}
}

func (x *CrossPaymentPrepareResMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentPrepareResMessage) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

type CrossPaymentCommitResMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pn     int64 `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	Result bool  `protobuf:"varint,2,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CrossPaymentCommitResMessage) Reset() {
	*x = CrossPaymentCommitResMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cross_server_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentCommitResMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentCommitResMessage) ProtoMessage() {}

func (x *CrossPaymentCommitResMessage) ProtoReflect() protoreflect.Message {
	mi := &file_cross_server_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentCommitResMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentCommitResMessage) Descriptor() ([]byte, []int) {
	return file_cross_server_proto_rawDescGZIP(), []int{1}
}

func (x *CrossPaymentCommitResMessage) GetPn() int64 {
	if x != nil {
		return x.Pn
	}
	return 0
}

func (x *CrossPaymentCommitResMessage) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

type CrossPaymentConfirmResMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result bool `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CrossPaymentConfirmResMessage) Reset() {
	*x = CrossPaymentConfirmResMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cross_server_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossPaymentConfirmResMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossPaymentConfirmResMessage) ProtoMessage() {}

func (x *CrossPaymentConfirmResMessage) ProtoReflect() protoreflect.Message {
	mi := &file_cross_server_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossPaymentConfirmResMessage.ProtoReflect.Descriptor instead.
func (*CrossPaymentConfirmResMessage) Descriptor() ([]byte, []int) {
	return file_cross_server_proto_rawDescGZIP(), []int{2}
}

func (x *CrossPaymentConfirmResMessage) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

type CrossResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result bool `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CrossResult) Reset() {
	*x = CrossResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cross_server_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrossResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrossResult) ProtoMessage() {}

func (x *CrossResult) ProtoReflect() protoreflect.Message {
	mi := &file_cross_server_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrossResult.ProtoReflect.Descriptor instead.
func (*CrossResult) Descriptor() ([]byte, []int) {
	return file_cross_server_proto_rawDescGZIP(), []int{3}
}

func (x *CrossResult) GetResult() bool {
	if x != nil {
		return x.Result
	}
	return false
}

var File_cross_server_proto protoreflect.FileDescriptor

var file_cross_server_proto_rawDesc = []byte{
	0x0a, 0x12, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x47, 0x0a, 0x1d, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x73, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x46, 0x0a,
	0x1c, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x52, 0x65, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x70, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x70, 0x6e, 0x12, 0x16, 0x0a,
	0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x37, 0x0a, 0x1d, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61,
	0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x52, 0x65, 0x73, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x25,
	0x0a, 0x0b, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x32, 0x9e, 0x01, 0x0a, 0x0c, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x5f,
	0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x46, 0x0a, 0x14, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x12, 0x1e,
	0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x65,
	0x70, 0x61, 0x72, 0x65, 0x52, 0x65, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x0c,
	0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x12, 0x46,
	0x0a, 0x15, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x12, 0x1d, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x50,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x65, 0x73, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x0c, 0x2e, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x22, 0x00, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cross_server_proto_rawDescOnce sync.Once
	file_cross_server_proto_rawDescData = file_cross_server_proto_rawDesc
)

func file_cross_server_proto_rawDescGZIP() []byte {
	file_cross_server_proto_rawDescOnce.Do(func() {
		file_cross_server_proto_rawDescData = protoimpl.X.CompressGZIP(file_cross_server_proto_rawDescData)
	})
	return file_cross_server_proto_rawDescData
}

var file_cross_server_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_cross_server_proto_goTypes = []interface{}{
	(*CrossPaymentPrepareResMessage)(nil), // 0: crossPaymentPrepareResMessage
	(*CrossPaymentCommitResMessage)(nil),  // 1: crossPaymentCommitResMessage
	(*CrossPaymentConfirmResMessage)(nil), // 2: crossPaymentConfirmResMessage
	(*CrossResult)(nil),                   // 3: crossResult
}
var file_cross_server_proto_depIdxs = []int32{
	0, // 0: Cross_Server.crossPaymentPrepared:input_type -> crossPaymentPrepareResMessage
	1, // 1: Cross_Server.crossPaymentCommitted:input_type -> crossPaymentCommitResMessage
	3, // 2: Cross_Server.crossPaymentPrepared:output_type -> crossResult
	3, // 3: Cross_Server.crossPaymentCommitted:output_type -> crossResult
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_cross_server_proto_init() }
func file_cross_server_proto_init() {
	if File_cross_server_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cross_server_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentPrepareResMessage); i {
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
		file_cross_server_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentCommitResMessage); i {
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
		file_cross_server_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossPaymentConfirmResMessage); i {
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
		file_cross_server_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrossResult); i {
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
			RawDescriptor: file_cross_server_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cross_server_proto_goTypes,
		DependencyIndexes: file_cross_server_proto_depIdxs,
		MessageInfos:      file_cross_server_proto_msgTypes,
	}.Build()
	File_cross_server_proto = out.File
	file_cross_server_proto_rawDesc = nil
	file_cross_server_proto_goTypes = nil
	file_cross_server_proto_depIdxs = nil
}
