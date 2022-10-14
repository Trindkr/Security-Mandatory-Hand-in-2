package main

import (
	gRPC "github.com/Trindkr/Security-Mandatory-Hand-in-2-golang/proto"
)

type Bob struct {
	gRPC.UnimplementedCommitmentServiceServer
}

// func (s *Server) ValidateCommitment(ctx context.Context, commitment *Commitment) (*gRPC.Commitment_Res, error) {
    
//     //ack :=  // make an instance of your return type
//     return (ack, nil)
// }