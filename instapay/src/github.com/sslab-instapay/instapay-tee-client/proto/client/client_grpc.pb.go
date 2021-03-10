// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package client

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ClientClient is the client API for Client service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ClientClient interface {
	AgreementRequest(ctx context.Context, in *AgreeRequestsMessage, opts ...grpc.CallOption) (*AgreementResult, error)
	UpdateRequest(ctx context.Context, in *UpdateRequestsMessage, opts ...grpc.CallOption) (*UpdateResult, error)
	ConfirmPayment(ctx context.Context, in *ConfirmRequestsMessage, opts ...grpc.CallOption) (*ConfirmResult, error)
	DirectChannelPayment(ctx context.Context, in *DirectChannelPaymentMessage, opts ...grpc.CallOption) (*DirectPaymentResult, error)
	CrossPaymentPrepareClientRequest(ctx context.Context, in *CrossPaymentPrepareReqClientMessage, opts ...grpc.CallOption) (*PrepareResult, error)
	CrossPaymentCommitClientRequest(ctx context.Context, in *CrossPaymentCommitReqClientMessage, opts ...grpc.CallOption) (*CommitResult, error)
	CrossPaymentConfirmClientRequest(ctx context.Context, in *CrossPaymentConfirmReqClientMessage, opts ...grpc.CallOption) (*ConfirmResult, error)
	CrossPaymentRefundClientRequest(ctx context.Context, in *CrossPaymentRefundReqClientMessage, opts ...grpc.CallOption) (*RefundResult, error)
}

type clientClient struct {
	cc grpc.ClientConnInterface
}

func NewClientClient(cc grpc.ClientConnInterface) ClientClient {
	return &clientClient{cc}
}

func (c *clientClient) AgreementRequest(ctx context.Context, in *AgreeRequestsMessage, opts ...grpc.CallOption) (*AgreementResult, error) {
	out := new(AgreementResult)
	err := c.cc.Invoke(ctx, "/Client/agreementRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) UpdateRequest(ctx context.Context, in *UpdateRequestsMessage, opts ...grpc.CallOption) (*UpdateResult, error) {
	out := new(UpdateResult)
	err := c.cc.Invoke(ctx, "/Client/updateRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) ConfirmPayment(ctx context.Context, in *ConfirmRequestsMessage, opts ...grpc.CallOption) (*ConfirmResult, error) {
	out := new(ConfirmResult)
	err := c.cc.Invoke(ctx, "/Client/confirmPayment", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) DirectChannelPayment(ctx context.Context, in *DirectChannelPaymentMessage, opts ...grpc.CallOption) (*DirectPaymentResult, error) {
	out := new(DirectPaymentResult)
	err := c.cc.Invoke(ctx, "/Client/directChannelPayment", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) CrossPaymentPrepareClientRequest(ctx context.Context, in *CrossPaymentPrepareReqClientMessage, opts ...grpc.CallOption) (*PrepareResult, error) {
	out := new(PrepareResult)
	err := c.cc.Invoke(ctx, "/Client/crossPaymentPrepareClientRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) CrossPaymentCommitClientRequest(ctx context.Context, in *CrossPaymentCommitReqClientMessage, opts ...grpc.CallOption) (*CommitResult, error) {
	out := new(CommitResult)
	err := c.cc.Invoke(ctx, "/Client/crossPaymentCommitClientRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) CrossPaymentConfirmClientRequest(ctx context.Context, in *CrossPaymentConfirmReqClientMessage, opts ...grpc.CallOption) (*ConfirmResult, error) {
	out := new(ConfirmResult)
	err := c.cc.Invoke(ctx, "/Client/crossPaymentConfirmClientRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clientClient) CrossPaymentRefundClientRequest(ctx context.Context, in *CrossPaymentRefundReqClientMessage, opts ...grpc.CallOption) (*RefundResult, error) {
	out := new(RefundResult)
	err := c.cc.Invoke(ctx, "/Client/crossPaymentRefundClientRequest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClientServer is the server API for Client service.
// All implementations must embed UnimplementedClientServer
// for forward compatibility
type ClientServer interface {
	AgreementRequest(context.Context, *AgreeRequestsMessage) (*AgreementResult, error)
	UpdateRequest(context.Context, *UpdateRequestsMessage) (*UpdateResult, error)
	ConfirmPayment(context.Context, *ConfirmRequestsMessage) (*ConfirmResult, error)
	DirectChannelPayment(context.Context, *DirectChannelPaymentMessage) (*DirectPaymentResult, error)
	CrossPaymentPrepareClientRequest(context.Context, *CrossPaymentPrepareReqClientMessage) (*PrepareResult, error)
	CrossPaymentCommitClientRequest(context.Context, *CrossPaymentCommitReqClientMessage) (*CommitResult, error)
	CrossPaymentConfirmClientRequest(context.Context, *CrossPaymentConfirmReqClientMessage) (*ConfirmResult, error)
	CrossPaymentRefundClientRequest(context.Context, *CrossPaymentRefundReqClientMessage) (*RefundResult, error)
	mustEmbedUnimplementedClientServer()
}

// UnimplementedClientServer must be embedded to have forward compatible implementations.
type UnimplementedClientServer struct {
}

func (UnimplementedClientServer) AgreementRequest(context.Context, *AgreeRequestsMessage) (*AgreementResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AgreementRequest not implemented")
}
func (UnimplementedClientServer) UpdateRequest(context.Context, *UpdateRequestsMessage) (*UpdateResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateRequest not implemented")
}
func (UnimplementedClientServer) ConfirmPayment(context.Context, *ConfirmRequestsMessage) (*ConfirmResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConfirmPayment not implemented")
}
func (UnimplementedClientServer) DirectChannelPayment(context.Context, *DirectChannelPaymentMessage) (*DirectPaymentResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DirectChannelPayment not implemented")
}
func (UnimplementedClientServer) CrossPaymentPrepareClientRequest(context.Context, *CrossPaymentPrepareReqClientMessage) (*PrepareResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CrossPaymentPrepareClientRequest not implemented")
}
func (UnimplementedClientServer) CrossPaymentCommitClientRequest(context.Context, *CrossPaymentCommitReqClientMessage) (*CommitResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CrossPaymentCommitClientRequest not implemented")
}
func (UnimplementedClientServer) CrossPaymentConfirmClientRequest(context.Context, *CrossPaymentConfirmReqClientMessage) (*ConfirmResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CrossPaymentConfirmClientRequest not implemented")
}
func (UnimplementedClientServer) CrossPaymentRefundClientRequest(context.Context, *CrossPaymentRefundReqClientMessage) (*RefundResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CrossPaymentRefundClientRequest not implemented")
}
func (UnimplementedClientServer) mustEmbedUnimplementedClientServer() {}

// UnsafeClientServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ClientServer will
// result in compilation errors.
type UnsafeClientServer interface {
	mustEmbedUnimplementedClientServer()
}

func RegisterClientServer(s grpc.ServiceRegistrar, srv ClientServer) {
	s.RegisterService(&Client_ServiceDesc, srv)
}

func _Client_AgreementRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AgreeRequestsMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).AgreementRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/agreementRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).AgreementRequest(ctx, req.(*AgreeRequestsMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_UpdateRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateRequestsMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).UpdateRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/updateRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).UpdateRequest(ctx, req.(*UpdateRequestsMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_ConfirmPayment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConfirmRequestsMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).ConfirmPayment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/confirmPayment",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).ConfirmPayment(ctx, req.(*ConfirmRequestsMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_DirectChannelPayment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DirectChannelPaymentMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).DirectChannelPayment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/directChannelPayment",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).DirectChannelPayment(ctx, req.(*DirectChannelPaymentMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_CrossPaymentPrepareClientRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CrossPaymentPrepareReqClientMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).CrossPaymentPrepareClientRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/crossPaymentPrepareClientRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).CrossPaymentPrepareClientRequest(ctx, req.(*CrossPaymentPrepareReqClientMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_CrossPaymentCommitClientRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CrossPaymentCommitReqClientMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).CrossPaymentCommitClientRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/crossPaymentCommitClientRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).CrossPaymentCommitClientRequest(ctx, req.(*CrossPaymentCommitReqClientMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_CrossPaymentConfirmClientRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CrossPaymentConfirmReqClientMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).CrossPaymentConfirmClientRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/crossPaymentConfirmClientRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).CrossPaymentConfirmClientRequest(ctx, req.(*CrossPaymentConfirmReqClientMessage))
	}
	return interceptor(ctx, in, info, handler)
}

func _Client_CrossPaymentRefundClientRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CrossPaymentRefundReqClientMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientServer).CrossPaymentRefundClientRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Client/crossPaymentRefundClientRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientServer).CrossPaymentRefundClientRequest(ctx, req.(*CrossPaymentRefundReqClientMessage))
	}
	return interceptor(ctx, in, info, handler)
}

// Client_ServiceDesc is the grpc.ServiceDesc for Client service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Client_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "Client",
	HandlerType: (*ClientServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "agreementRequest",
			Handler:    _Client_AgreementRequest_Handler,
		},
		{
			MethodName: "updateRequest",
			Handler:    _Client_UpdateRequest_Handler,
		},
		{
			MethodName: "confirmPayment",
			Handler:    _Client_ConfirmPayment_Handler,
		},
		{
			MethodName: "directChannelPayment",
			Handler:    _Client_DirectChannelPayment_Handler,
		},
		{
			MethodName: "crossPaymentPrepareClientRequest",
			Handler:    _Client_CrossPaymentPrepareClientRequest_Handler,
		},
		{
			MethodName: "crossPaymentCommitClientRequest",
			Handler:    _Client_CrossPaymentCommitClientRequest_Handler,
		},
		{
			MethodName: "crossPaymentConfirmClientRequest",
			Handler:    _Client_CrossPaymentConfirmClientRequest_Handler,
		},
		{
			MethodName: "crossPaymentRefundClientRequest",
			Handler:    _Client_CrossPaymentRefundClientRequest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "client.proto",
}
