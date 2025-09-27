// tlsparser.go
package tlsparser

import (
	"context"
	"fmt"
	"time"

	pb "go-tls-parser-client/go-client/Tls13Parser"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ContentType int

const (
	Handshake ContentType = iota // 0
	ApplicationData              // 1
	Alert                        // 2
	ChangeCipherSpec             // 3
	Heartbeat                    // 4
)

// make ContentType printable
func (ct ContentType) String() string {
	return [...]string{"Handshake", "ApplicationData", "Alert", "ChangeCipherSpec", "Heartbeat"}[ct]
}

type Client struct {
	conn      *grpc.ClientConn
	rpcClient pb.TlsParserClient
}

// NewClient creates and returns a new client connected to the given address.
func NewClient(address string) (*Client, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %w", err)
	}

	return &Client{
		conn:      conn,
		rpcClient: pb.NewTlsParserClient(conn),
	}, nil
}

// function to terminate the client's gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) ParseData(ctx context.Context, contentType ContentType, data string) (*pb.Handshake, error) {
	// TODO: implement different data types
	fmt.Printf("Parsing data of type: %s\n", contentType)

	// Define timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Call the SayHello RPC
	r, err := c.rpcClient.SayHello(ctx, &pb.HandshakeRequest{Data: data})
	if err != nil {
		return nil, fmt.Errorf("gRPC call failed: %w", err)
	}

	return r.GetHandshake(), nil
}