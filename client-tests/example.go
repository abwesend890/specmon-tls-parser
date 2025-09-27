// main.go (in your other project)
package main

import (
	"context"
	"log"

	// This is how you'd import your new library.
	// Replace "your-module-name/go-client" with your actual module path.
	"go-tls-parser-client"
)

const (
	grpcAddress = "localhost:50051"
)

func main() {
	// Create a new client instance. This is done once.
	client, err := tlsparser.NewClient(grpcAddress)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	// Ensure the connection is closed when the program exits.
	defer client.Close()

	// Prepare the data to be parsed.
	data := "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"

	// Call the ParseData function from your library.
	// We pass the enum constant for the content type.
	handshake, err := client.ParseData(context.Background(), tlsparser.Handshake, data)
	if err != nil {
		log.Fatalf("Failed to parse data: %v", err)
	}

	// Print the result.
	log.Printf("Successfully parsed handshake: %v", handshake)
}