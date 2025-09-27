# server.py
import grpc
from concurrent import futures
import time

from grpc_reflection.v1alpha import reflection

from scapy.layers.tls.handshake import TLS13NewSessionTicket

# Import the generated classes
import tls13_pb2, tls13_pb2_grpc

import tls13_parser


class TlsParserServicer(tls13_pb2_grpc.TlsParserServicer):
    def SayHello(self, request, context):
        print(f"Received request with data: {request.data}")
        length_prefix = format(int(len(request.data) / 2), "x").zfill(4)
        # handshake message + TLS1.2 identification
        handshake_prefix = "16" + "0303" + length_prefix
        prefixed_request_data = handshake_prefix + request.data
        try:
            parsed_data: TLS13NewSessionTicket = tls13_parser.parse_tls13(
                prefixed_request_data
            )
            parsed_as_dict = dict(parsed_data[1][0].fields)
            for key in ["msgtype", "msglen", "noncelen", "ticketlen", "extlen", "ext"]:
                if key in parsed_as_dict:
                    del parsed_as_dict[key]
            response_dict = dict(handshake=dict(new_session_ticket=parsed_as_dict))
            return tls13_pb2.HandshakeResponse(**response_dict)
        except Exception as e:
            print(f"Error parsing {request.data}; error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"An error occurred: {e}")
            return tls13_pb2.HandshakeResponse()


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    tls13_pb2_grpc.add_TlsParserServicer_to_server(TlsParserServicer(), server)

    SERVICE_NAMES = (
        tls13_pb2.DESCRIPTOR.services_by_name["TlsParser"].full_name,
        reflection.SERVICE_NAME,
    )

    reflection.enable_server_reflection(SERVICE_NAMES, server)

    print("Starting server. Listening on port 50051. Reflection is enabled.")
    server.add_insecure_port("[::]:50051")
    server.start()

    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()
