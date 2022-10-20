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
	rand.Seed(time.Now().UnixNano()) //Seed the random number generator. The seed has to be different from the server, otherwise it will produce the same random number
	flag.Parse()
	connectToBob()
}

func roll() {
	aliceRndm, bobRndm := CommitRandomNumber()
	aliceValidiatedRndm := validateMessage(aliceRndm)
	calcRoll := calculateDieRoll(aliceValidiatedRndm, bobRndm)
	fmt.Println("Die roll is: ", calcRoll)
}

//Generate a random number, hash it, and send it to Bob.
func CommitRandomNumber() (int64, int64) {
	aliceRndm := rand.Int63()
	fmt.Println("Alice generates a ramdom number: ", aliceRndm)

	commitment := sha1.New().Sum([]byte(fmt.Sprint(aliceRndm))) //Hash random number
	fmt.Println("Alice hashes her random number and sends commits it to Bob: ", commitment)

	res, err := bob.CommitMsg(context.Background(), &gRPC.Message{HashedRandom: commitment}) //Commit hashed random. this also returns Bob's random number.
	if err != nil {
		log.Fatal("Error occured. Could not commit message: ", err)
	}
	return aliceRndm, res.Random
}

//Send Bob Alice's random number, used to validate Alice's commitment.
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

//Take the two randomly generated numbers from Bob and Alice and XOR them. Take modulo 6 to the result, and add 1.
//This produces a random value between 1 and 6.
func calculateDieRoll(aliceRdnm int64, bobRndm int64) int64 {
	return ((aliceRdnm ^ bobRndm) % 6) + 1
}

//Setup of TLS connection
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

	roll() //Start process of rolling a die.
	for {
	} //Infinite for loop keeps the connection open between server and client.

}
