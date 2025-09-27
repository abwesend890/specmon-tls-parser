// go-client/client.go
package main

import (
	"context"
	"log"
	"time"

	// Import the generated Go code package
	pb "go-client/Tls13Parser"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	address = "localhost:50051"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Create a new Greeter client
	c := pb.NewTlsParserClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Call the SayHello RPC
	data := "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"
	r, err := c.SayHello(ctx, &pb.HandshakeRequest{Data: data})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	log.Printf("Greeting from server: %s", r.Handshake)
}