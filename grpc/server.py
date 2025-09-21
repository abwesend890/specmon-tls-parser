import grpc
from concurrent import futures
import time

from scapy.layers.tls.handshake import TLS13NewSessionTicket

# Import the generated classes
import tls13_pb2, tls13_pb2_grpc

import tls13_parser


# Create a class to define the server functions, derived from
# test_pb2_grpc.GreeterServicer
class GreeterServicer(tls13_pb2_grpc.TlsParserServicer):
    def SayHello(self, request, context):
        print(f"Received request with data: {request.data}")

        # handle prefix
        length_prefix = format(int(len(request.data) / 2), 'x').zfill(4)
        handshake_prefix = "16" + "0303" + length_prefix # handshake message + TLS1.2 identification
        prefixed_request_data = handshake_prefix + request.data

        # parse data
        # TODO make generic: New Session Ticket
        parsed_data: TLS13NewSessionTicket = tls13_parser.parse_tls13(prefixed_request_data)
        parsed_as_dict = dict(parsed_data[1][0].fields)
        len_as_string = format(parsed_as_dict.get("msglen"), 'x').zfill(4)
        try:
            # TODO handle other list contents?

            # parsed_as_dict["extensions"] = parsed_as_dict["ext"]
            # contained in the parsed request but not in the response model
            for key in ["msgtype", "msglen", "noncelen", "ticketlen", "extlen", "ext"]:
                del parsed_as_dict[key]



            # create response
            response_dict = dict(handshake=dict(new_session_ticket=parsed_as_dict))
            response = tls13_pb2.HandshakeResponse(**response_dict)
            return response
        except ValueError as e:
            print(e)
        except Exception as e:
            print(f"Error parsing {request.data}; error: {e}")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    # Add the TlsParser service to the server
    tls13_pb2_grpc.add_TlsParserServicer_to_server(GreeterServicer(), server)

    # Listen on port 50051
    print("Starting server. Listening on port 50051.")
    server.add_insecure_port('[::]:50051')
    server.start()

    # Keep the server running
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    serve()