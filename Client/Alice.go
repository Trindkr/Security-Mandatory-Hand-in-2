package main

import (

	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"

	gRPC "github.com/Trindkr/Security-Mandatory-Hand-in-2-golang/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var bob gRPC.CommitmentServiceClient
var addr = flag.String("addr", "localhost:50051", "the address to connect to")

func main() {
	flag.Parse()

	connectToBob()
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
	log.Println("Connected to Bob")

}
