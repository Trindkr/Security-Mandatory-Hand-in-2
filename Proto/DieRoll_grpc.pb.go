// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

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

// CommitmentServiceClient is the client API for CommitmentService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CommitmentServiceClient interface {
	CommitMsg(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Message_Res, error)
	ValidateCommitment(ctx context.Context, in *Validate_Message, opts ...grpc.CallOption) (*Validate_Message_Res, error)
}

type commitmentServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCommitmentServiceClient(cc grpc.ClientConnInterface) CommitmentServiceClient {
	return &commitmentServiceClient{cc}
}

func (c *commitmentServiceClient) CommitMsg(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Message_Res, error) {
	out := new(Message_Res)
	err := c.cc.Invoke(ctx, "/proto.CommitmentService/CommitMsg", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *commitmentServiceClient) ValidateCommitment(ctx context.Context, in *Validate_Message, opts ...grpc.CallOption) (*Validate_Message_Res, error) {
	out := new(Validate_Message_Res)
	err := c.cc.Invoke(ctx, "/proto.CommitmentService/ValidateCommitment", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CommitmentServiceServer is the server API for CommitmentService service.
// All implementations must embed UnimplementedCommitmentServiceServer
// for forward compatibility
type CommitmentServiceServer interface {
	CommitMsg(context.Context, *Message) (*Message_Res, error)
	ValidateCommitment(context.Context, *Validate_Message) (*Validate_Message_Res, error)
	mustEmbedUnimplementedCommitmentServiceServer()
}

// UnimplementedCommitmentServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCommitmentServiceServer struct {
}

func (UnimplementedCommitmentServiceServer) CommitMsg(context.Context, *Message) (*Message_Res, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CommitMsg not implemented")
}
func (UnimplementedCommitmentServiceServer) ValidateCommitment(context.Context, *Validate_Message) (*Validate_Message_Res, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateCommitment not implemented")
}
func (UnimplementedCommitmentServiceServer) mustEmbedUnimplementedCommitmentServiceServer() {}

// UnsafeCommitmentServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CommitmentServiceServer will
// result in compilation errors.
type UnsafeCommitmentServiceServer interface {
	mustEmbedUnimplementedCommitmentServiceServer()
}

func RegisterCommitmentServiceServer(s grpc.ServiceRegistrar, srv CommitmentServiceServer) {
	s.RegisterService(&CommitmentService_ServiceDesc, srv)
}

func _CommitmentService_CommitMsg_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Message)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CommitmentServiceServer).CommitMsg(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.CommitmentService/CommitMsg",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CommitmentServiceServer).CommitMsg(ctx, req.(*Message))
	}
	return interceptor(ctx, in, info, handler)
}

func _CommitmentService_ValidateCommitment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Validate_Message)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CommitmentServiceServer).ValidateCommitment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.CommitmentService/ValidateCommitment",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CommitmentServiceServer).ValidateCommitment(ctx, req.(*Validate_Message))
	}
	return interceptor(ctx, in, info, handler)
}

// CommitmentService_ServiceDesc is the grpc.ServiceDesc for CommitmentService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CommitmentService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.CommitmentService",
	HandlerType: (*CommitmentServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CommitMsg",
			Handler:    _CommitmentService_CommitMsg_Handler,
		},
		{
			MethodName: "ValidateCommitment",
			Handler:    _CommitmentService_ValidateCommitment_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/dieroll.proto",
}
