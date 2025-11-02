#!/usr/bin/env python
import struct
from http.client import responses
from typing import Union, List

# server.py
import grpc
from concurrent import futures
import time

from loguru import logger
from scapy.layers.tls.record import TLSChangeCipherSpec, TLSApplicationData
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.packet import Raw

import utils.logging_config  # noqa: F401
from utils.conversions import int_to_bytes
from grpc_reflection.v1alpha import reflection

# from scapy.layers.tls.handshake import TLSClientHello, TLS13NewSessionTicket
import scapy

from scapy.layers.tls.extensions import TLS_Ext_Unknown
from scapy.layers.tls.handshake import (
    TLS13ClientHello,
    TLS13ServerHello,
    TLS13NewSessionTicket,
    TLS13Certificate,
    TLS13CertificateRequest,
    TLS13KeyUpdate,
    TLS13EndOfEarlyData,
    TLS13HelloRetryRequest,
    TLSClientHello,
)

# Import the generated classes
import tls13_pb2, tls13_pb2_grpc

import tls13_parser


def grpc_encode(parse_response: dict):
    return tls13_pb2.ParseResponse(**parse_response)


class TlsParserServicer(tls13_pb2_grpc.TlsParserServicer):
    def Split(self, request: tls13_pb2.SplitRequest, context):
        logger.info(f"Received request with data: {request.data}")
        data: str = request.data
        pos: int = request.pos
        part1, part2 = data.split(pos)
        return tls13_pb2.SplitResponse(part1=part1, part2=part2)

    def ParseHelloRetryRequest(self, request, context):
        logger.info(f"Received request with data: {request.data.hex()}")

        # prefix data in case we do not have equal number of bytes
        data = request.data
        try:
            return grpc_encode(
                tls13_parser.parse_tls13_cached(
                    data, known_content_type=tls13_parser.ContentType.HelloRetryRequest
                )
            )

        except AssertionError as e:
            logger.exception(e)
            raise e
        except Exception as e:
            logger.error(f"Error parsing {request.data}; error: {e}")
            logger.exception(e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"An error occurred: {e}")
            raise e

    def Parse(self, request, context):
        logger.info(f"Received request with data: {request.data.hex()}")

        # prefix data in case we do not have equal number of bytes
        data = request.data
        try:
            return grpc_encode(tls13_parser.parse_tls13_cached(data))

        except AssertionError as e:
            logger.exception(e)
            raise e
        except Exception as e:
            logger.error(f"Error parsing {request.data}; error: {e}")
            logger.exception(e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"An error occurred: {e}")
            raise e

    # def ParseDecryptedTODO(self):
    #     logger.info(f"Received request with data: {request.data.hex()}")
    #
    #     # prefix data in case we do not have equal number of bytes
    #     data = request.data
    #     # if len(data) % 2 != 0:
    #     #     logger.debug("Prefixing with '00'... ")
    #     #     data = bytes.fromhex("00") + data
    #
    #     # length_prefix = format(int(len(request.data) / 2), "x").zfill(4)
    #     # handshake message + TLS1.2 identification
    #     # handshake_prefix = bytes.fromhex("16" + "0303" + length_prefix)
    #     # prefixed_request_data = handshake_prefix + request.data
    #     # try:
    #     # parsed_data = tls13_parser.parse_tls13(
    #     #     prefixed_request_data
    #     # )
    #
    #     try:
    #         parsed_data = tls13_parser.parse_tls13_cached(data)
    #         # if len(parsed_data) != 1:
    #         #     raise NotImplementedError(
    #         #         "Attempting to parse exactly 1 message, else we'd need to return a list"
    #         #     )
    #         # parsed_data = parsed_data[0]
    #         # str() returns a byte object on parsed_data
    #         # logger.debug(f"Received parsed data: {parsed_data.__str__().hex()}")
    #         # parsed_as_dict = dict(parsed_data[1][0].fields)
    #         return _handle_handshake(parsed_data)
    #
    #     except AssertionError as e:
    #         logger.exception(e)
    #         raise e
    #     except Exception as e:
    #         logger.error(f"Error parsing {request.data}; error: {e}")
    #         logger.exception(e)
    #         context.set_code(grpc.StatusCode.INTERNAL)
    #         context.set_details(f"An error occurred: {e}")
    #         raise e


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
