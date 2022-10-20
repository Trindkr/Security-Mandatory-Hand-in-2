package main

import (

	//"context"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"time"

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
	rand.Seed(time.Now().UnixNano() + 1) //Set random seed. The "+ 1" ensures the seed generated is different from Alice's.
	serverSetup()
}

func (b *Bob) CommitMsg(ctx context.Context, msg *gRPC.Message) (*gRPC.Message_Res, error) {
	fmt.Println("Bob recieved commitment: ", msg.GetHashedRandom())
	b.commitment = msg.GetHashedRandom()

	rndm := rand.Int63() //Generate Bob's random number
	b.bobRndm = rndm
	fmt.Println("Bob generates a random number: ", rndm)

	return &gRPC.Message_Res{Random: rndm}, nil
}

func (b *Bob) ValidateCommitment(ctx context.Context, msg *gRPC.Validate_Message) (*gRPC.Validate_Message_Res, error) {
	aliceRndm := msg.GetRandom()
	hashedRndm := sha1.New().Sum([]byte(fmt.Sprint(aliceRndm))) //Hash Alice's random number

	//Validate that Alice's commitment is equal to that of Alice's hashed random number.
	if !bytes.Equal(b.commitment, hashedRndm) {
		fmt.Println("Bob declared Alice's commitment invalid")
		return &gRPC.Validate_Message_Res{Validated: false}, nil
	}

	//Calculate the value of the die roll, using Alice and Bob's random number.
	calcRoll := calculateDieRoll(aliceRndm, b.bobRndm)

	fmt.Println("Bob declared Alice's commitment valid, and calculates die roll: ", calcRoll)

	return &gRPC.Validate_Message_Res{Validated: true, Roll: calcRoll}, nil

}

//Take the two randomly generated numbers from Bob and Alice and XOR them. Take modulo 6 to the result, and add 1.
//This produces a random value between 1 and 6.
func calculateDieRoll(aliceRdnm int64, bobRndm int64) int64 {
	return ((aliceRdnm ^ bobRndm) % 6) + 1
}

//Setup of server using TLS
func serverSetup() {
	flag.Parse()
	log.Printf("Bob starting on port %d...\n", *port)

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

	//Initialize bob with no random number and no commitment.
	bob := &Bob{
		bobRndm:    0,
		commitment: nil,
	}

	gRPC.RegisterCommitmentServiceServer(serv, bob)
	if err := serv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
