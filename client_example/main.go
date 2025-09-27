// main.go
package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	reflectpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

const (
	grpcAddress = "localhost:50051"
)

func main() {
	ctx := context.Background()

	// Connect to the gRPC server
	conn, err := grpc.Dial(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Could not establish connection: %v", err)
	}
	defer conn.Close()

	// Create a standard reflection stub 
	reflectStub := reflectpb.NewServerReflectionClient(conn)

	// Create the high-level jhump reflection client
	reflectClient := grpcreflect.NewClient(ctx, reflectStub)

	// Resolve the Service and Method Descriptors
	serviceName := "Tls13Parser.TlsParser"
	serviceDesc, err := reflectClient.ResolveService(serviceName)
	if err != nil {
		log.Fatalf("Service name '%s' could not be resolved: %v", serviceName, err)
	}

	methodName := "SayHello"
	methodDesc := serviceDesc.FindMethodByName(methodName)
	if methodDesc == nil {
		log.Fatalf("Method name '%s' could not be found.", methodName)
	}

	// Create a dynamic message and populate it
	request := dynamic.NewMessage(methodDesc.GetInputType())
	data := "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"
	request.SetFieldByName("data", data)

	// Create a dynamic stub and invoke the RPC
	stub := grpcdynamic.NewStub(conn)
	response, err := stub.InvokeRpc(ctx, methodDesc, request)
	if err != nil {
		log.Fatalf("RPC-Call failed: %v", err)
	}

	// convert response to JSON and print it
	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Fatalf("Unable to convert to JSON: %v", err)
	}

	log.Printf("Server Answer:\n%s\n", string(responseJSON))
}