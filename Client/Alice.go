package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"time"

	gRPC "github.com/Trindkr/Security-Mandatory-Hand-in-2-golang/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var bob gRPC.CommitmentServiceClient
var addr = flag.String("addr", "localhost:50051", "the address to connect to")

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()
	connectToBob()

}
func roll() {
	aliceRndm, bobRndm := rollAndCommit()
	aliceValidiatedRndm := validateMessage(aliceRndm)
	dieRoll := calculateDieRoll(aliceValidiatedRndm, bobRndm)
	fmt.Println("Die roll is: ", dieRoll)
}

func rollAndCommit() (int64, int64) {
	aliceRndm := rand.Int63()
	fmt.Println("Alice generates a ramdom number: ", aliceRndm)
	commitment := sha1.New().Sum([]byte(fmt.Sprint(aliceRndm)))
	fmt.Println("Alice hashes her random number and sends commits it to Bob: ", commitment)
	res, err := bob.CommitMsg(context.Background(), &gRPC.Message{HashedRandom: commitment})
	if err != nil {
		log.Fatal("Error occured. Could not commit message: ", err)
	}
	return aliceRndm, res.Random
}

func validateMessage(msg int64) int64 {
	res, err := bob.ValidateCommitment(context.Background(), &gRPC.Validate_Message{Random: msg})
	if err != nil {
		log.Fatal("Error occured. Could not validate message: ", err)
	}
	if !res.Validated {
		return 0
	}
	return msg
}

func calculateDieRoll(aliceRdnm int64, bobRndm int64) int64 {
	return ((aliceRdnm ^ bobRndm) % 6) + 1
}

func connectToBob() {

	cert, err := tls.LoadX509KeyPair("ssl-keys/client_cert.pem", "ssl-keys/client_key.pem")
	if err != nil {
		log.Fatalf("failed to load client cert: %v", err)
	}

	ca := x509.NewCertPool()
	caFilePath := "ssl-keys/ca_cert.pem"
	caBytes, err := ioutil.ReadFile(caFilePath)
	if err != nil {
		log.Fatalf("failed to read ca cert %q: %v", caFilePath, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("failed to parse %q", caFilePath)
	}

	tlsConfig := &tls.Config{
		ServerName:   "x.test.example.com",
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
	}

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	bob = gRPC.NewCommitmentServiceClient(conn)

	fmt.Println("Connected to Bob")

	roll()
	for  {} //Keep connection open.

}
