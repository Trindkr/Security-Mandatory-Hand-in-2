package main

import (

	//"context"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"

	gRPC "github.com/Trindkr/Security-Mandatory-Hand-in-2-golang/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Bob struct {
	gRPC.UnimplementedCommitmentServiceServer
	bobRndm    int64
	commitment []byte
}

var port = flag.Int("port", 50051, "the port to serve on")

func main() {

	serverSetup()
}

func (b *Bob) CommitMsg(ctx context.Context, msg *gRPC.Message) (*gRPC.Message_Res, error) {
	fmt.Println("Bob recieved commit: %v from Alice", msg.GetMsg())
	b.commitment = msg.GetMsg()
	rndm := rand.Int63()
	fmt.Println("Bob generates a random number: %v", rndm)
	b.bobRndm = rndm
	return &gRPC.Message_Res{Random: rndm}, nil
}

// func (b *Bob) Validate_Message(ctx context.Context, msg *gRPC.Validate_Message)(*gRPC.Validate_Message_Res, error){

// }

func serverSetup() {
	flag.Parse()
	log.Printf("Bob starting on port %d...\n", *port)

	//Setup of server certificate and private key
	cert, err := tls.LoadX509KeyPair("ssl-keys/server_cert.pem", "ssl-keys/server_key.pem")
	if err != nil {
		log.Fatalf("failed to load key pair: %s", err)
	}

	ca := x509.NewCertPool()
	caFilePath := "ssl-keys/client_ca_cert.pem"
	caBytes, err := ioutil.ReadFile(caFilePath)
	if err != nil {
		log.Fatalf("failed to read ca cert %q: %v", caFilePath, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("failed to parse %q", caFilePath)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
	}
	serv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	bob := &Bob{
		bobRndm:    0,
		commitment: nil,
	}

	gRPC.RegisterCommitmentServiceServer(serv, bob)
	if err := serv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
