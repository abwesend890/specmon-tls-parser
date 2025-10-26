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
    parsed_list: List[_GenericTLSSessionInheritance],
):

    parse_response = list()
    for parsed in parsed_list:
        parse_response_message = dict()
        logger.debug(f"In handle Handshake with type {type(parsed)}")

        #  HELLO RETRY REQUEST
        if isinstance(parsed, TLS13HelloRetryRequest):
            of_interest_scapy_mapping = dict(
                version="legacy_version",
                random_bytes="random",
                sid="legacy_session_id_echo",
                cipher="cipher_suites",
                comp="legacy_compression_methods",
                ext="extensions",
            )
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["hello_retry_request"] = answer
            parse_response.append(parse_response_message)
            continue

        #  NEW SESSION TICKET
        if isinstance(parsed, TLS13NewSessionTicket):
            of_interest_scapy_mapping = dict(
                ticket_lifetime="ticket_lifetime",
                ticket_age_add="ticket_age_add",
                ticket_nonce="ticket_nonce",
                ticket="ticket",
            )
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["new_session_ticket"] = answer
            parse_response.append(parse_response_message)
            # parse_response_message = dict(new_session_ticket=answer)
            # return tls13_pb2.ParseResponse(**parse_response_message)
            continue

        if isinstance(parsed, TLS13ClientHello):
            of_interest_scapy_mapping = dict(
                version="legacy_version",
                random_bytes="random",
                ciphers="cipher_suites",
                sid="legacy_session_id",
                comp="legacy_compression_methods",
                ext="extensions",
            )

            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["client_hello"] = answer
            # parse_response_message = dict(client_hello=answer)
            # return tls13_pb2.ParseResponse(**parse_response_message)
            parse_response.append(parse_response_message)
            continue

        if isinstance(parsed, TLSChangeCipherSpec):
            of_interest_scapy_mapping = dict(msgtype="change_cipher_spec")
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["change_cipher_spec"] = answer
            # parse_response_message = dict(change_cipher_spec=answer)
            # return tls13_pb2.ParseResponse(**parse_response_message)
            parse_response.append(parse_response_message)
            continue

        if isinstance(parsed, TLSApplicationData):
            of_interest_scapy_mapping = dict(data="application_data")
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["application_data"] = answer
            # parse_response_message = dict(application_data=answer)
            parse_response.append(parse_response_message)
            continue

        if isinstance(parsed, Raw):
            of_interest_scapy_mapping = dict(load="load")
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["raw"] = answer
            parse_response.append(parse_response_message)
            continue

        if isinstance(parsed, TLS13ServerHello):
            of_interest_scapy_mapping = dict(
                version="legacy_version",
                random_bytes="random",
                sid="legacy_session_id_echo",
                cipher="cipher_suites",
                comp="legacy_compression_methods",
                ext="extensions",
            )
            answer = _format_fields(parsed, of_interest_scapy_mapping)
            parse_response_message["server_hello"] = answer
            parse_response.append(parse_response_message)
            continue

        raise NotImplementedError(f"handling of {type(parsed)} is not implemented")
    return tls13_pb2.ParseResponse(**dict(messages=parse_response))


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
            parsed_data = tls13_parser.parse_tls13_cached(
                data, known_content_type=tls13_parser.ContentType.HelloRetryRequest
            )
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

    def Parse(self, request, context):
        logger.info(f"Received request with data: {request.data.hex()}")

        # prefix data in case we do not have equal number of bytes
        data = request.data
        try:
            parsed_data = tls13_parser.parse_tls13_cached(data)
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
