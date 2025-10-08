#!/usr/bin/env python
import struct
from http.client import responses
from typing import Union

# server.py
import grpc
from concurrent import futures
import time

from loguru import logger
from scapy.layers.tls.record import TLSChangeCipherSpec

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
)

# Import the generated classes
import tls13_pb2, tls13_pb2_grpc

import tls13_parser


def _format_field_value(field, value):
    if isinstance(value, bytes):
        return value
    elif isinstance(value, int):
        return field.struct.pack(value)
    elif isinstance(value, list):
        if all(isinstance(item, int) for item in value):
            return b"".join(map(lambda x: field.struct.pack(x), value))
        if all(isinstance(item, TLS_Ext_Unknown) for item in value):
            return b"".join(map(lambda x: x.original, value))

    raise NotImplementedError(
        f"Not implemented return type: {type(value)}. Need conversion to bytes"
    )


def _get_field_value(parsed, field) -> bytes:
    logger.debug(f"value of {field.name}: {getattr(parsed, field.name)}")
    value = getattr(parsed, field.name)
    return _format_field_value(field, value)


def _format_fields(parsed, of_interest_mapping: dict):
    answer = dict()
    for field in parsed.fields_desc:
        if not field.name in of_interest_mapping.keys():
            logger.warning(
                f"Not including attribute '{field.name}' of {type(parsed)} in response. Would be '{_get_field_value(parsed, field)}'"
            )
            continue
        value = _get_field_value(parsed, field)
        assert (
            value in parsed.original
        ), f"constructed value {value} not found in original {parsed.original}"
        answer[of_interest_mapping[field.name]] = value
    return answer


def _handle_handshake(
    parsed: Union[
        TLS13ClientHello
        | TLS13ServerHello
        | TLS13NewSessionTicket
        | TLS13Certificate
        | TLS13CertificateRequest
        | TLS13KeyUpdate
        | TLS13EndOfEarlyData
    ],
):
    logger.debug(f"In handle Handshake with type {type(parsed)}")
    parsed_fields = parsed.fields

    general_unwanted_fields = ["msgtype", "msglen"]
    #  NEW SESSION TICKET
    if isinstance(parsed, TLS13NewSessionTicket):
        of_interest_scapy_mapping = dict(
            ticket_lifetime="ticket_lifetime",
            ticket_age_add="ticket_age_add",
            ticket_nonce="ticket_nonce",
            ticket="ticket",
        )
        answer = _format_fields(parsed, of_interest_scapy_mapping)
        response_dict = dict(new_session_ticket=answer)
        return tls13_pb2.HandshakeResponse(**response_dict)

    if isinstance(parsed, TLS13ClientHello):
        of_interest_scapy_mapping = dict(
            version="legacy_version",
            random_bytes="random",
            sid="legacy_session_id",
            comp="legacy_compression_methods",
            ext="extensions",
        )

        answer = _format_fields(parsed, of_interest_scapy_mapping)
        response_dict = dict(client_hello=answer)
        return tls13_pb2.HandshakeResponse(**response_dict)

    if isinstance(parsed, TLSChangeCipherSpec):
        of_interest_scapy_mapping = dict(msgtype="change_cipher_spec")
        answer = _format_fields(parsed, of_interest_scapy_mapping)
        response_dict = dict(change_cipher_spec=answer)
        return tls13_pb2.HandshakeResponse(**response_dict)

    raise NotImplementedError(f"handling of {type(parsed)} is not implemented")


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
            parsed_data = tls13_parser.parse_tls13(data)
            if len(parsed_data) != 1:
                raise NotImplementedError(
                    "Attempting to parse exactly 1 message, else we'd need to return a list"
                )
            parsed_data = parsed_data[0]
            # str() returns a byte object on parsed_data
            logger.debug(f"Received parsed data: {parsed_data.__str__().hex()}")
            # parsed_as_dict = dict(parsed_data[1][0].fields)
            return _handle_handshake(parsed_data)

        except AssertionError as e:
            logger.exception(e)
            raise e
        except Exception as e:
            logger.error(f"Error parsing {request.data}; error: {e}")
            logger.exception(e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"An error occurred: {e}")
            raise e


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
