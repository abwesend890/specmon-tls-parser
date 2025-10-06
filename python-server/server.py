#!/usr/bin/env python

# server.py
import grpc
from concurrent import futures
import time

from loguru import logger
import utils.logging_config  # noqa: F401

from grpc_reflection.v1alpha import reflection

# from scapy.layers.tls.handshake import TLSClientHello, TLS13NewSessionTicket
import scapy

# Import the generated classes
import tls13_pb2, tls13_pb2_grpc

import tls13_parser

def _handle_Handshake(parsed):
    assert len(parsed) == 2
    assert len(parsed[1]) == 1
    logger.debug(f"In handle Handshake with type {type(parsed[1][0])}")
    parsed_fields = parsed[1][0].fields

    #  NEW SESSION TICKET
    if isinstance(parsed[1][0], scapy.layers.tls.handshake.TLS13NewSessionTicket):
        for key in ["msgtype", "msglen", "noncelen", "ticketlen", "extlen", "ext"]:
            if key in parsed_fields:
                del parsed_fields[key]
        response_dict = dict(handshake=dict(new_session_ticket=dict(parsed_fields)))
        return tls13_pb2.HandshakeResponse(**response_dict)

    if isinstance(parsed[1][0], scapy.layers.tls.handshake.TLSClientHello):
        logger.debug("IN TLS CLIENT HELLO")
        raise NotImplementedError

    raise NotImplementedError


class TlsParserServicer(tls13_pb2_grpc.TlsParserServicer):
    def Split(self, request: tls13_pb2.SplitRequest, context):
        logger.info(f"Received request with data: {request.data}")
        data: str = request.data
        pos: int = request.pos
        part1, part2 = data.split(pos)
        return tls13_pb2.SplitResponse(part1=part1, part2=part2)


    def Handshake(self, request, context):
        logger.info(f"Received request with data: {request.data.hex()}")

        # prefix data in case we do not have equal number of bytes
        data = request.data
        # if len(data) % 2 != 0:
        #     logger.debug("Prefixing with '00'... ")
        #     data = bytes.fromhex("00") + data


        # length_prefix = format(int(len(request.data) / 2), "x").zfill(4)
        # handshake message + TLS1.2 identification
        # handshake_prefix = bytes.fromhex("16" + "0303" + length_prefix)
        # prefixed_request_data = handshake_prefix + request.data
        # try:
            # parsed_data = tls13_parser.parse_tls13(
            #     prefixed_request_data
            # )

        try:
            logger.debug("Sending data to scapy TLS Parser")
            parsed_data = tls13_parser.parse_tls13(
                data
            )
            logger.debug(f"Received parsed data: {parsed_data}")
            # parsed_as_dict = dict(parsed_data[1][0].fields)
            return _handle_Handshake(parsed_data)

        except Exception as e:
            logger.error("Parser encountered error with type: " + str(type(e)))
            logger.error(f"Error parsing {request.data}; error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"An error occurred: {e}")
            raise e
            # return tls13_pb2.HandshakeResponse()


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    tls13_pb2_grpc.add_TlsParserServicer_to_server(TlsParserServicer(), server)

    SERVICE_NAMES = (
        tls13_pb2.DESCRIPTOR.services_by_name["TlsParser"].full_name,
        reflection.SERVICE_NAME,
    )

    reflection.enable_server_reflection(SERVICE_NAMES, server)

    logger.info("Starting server. Listening on port 50051. Reflection is enabled.")
    server.add_insecure_port("[::]:50051")
    server.start()

    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)
    except Exception as e:
        logger.exception("Unexpected exception occurred: %s", e)
        server.stop(1)


if __name__ == "__main__":
    serve()
