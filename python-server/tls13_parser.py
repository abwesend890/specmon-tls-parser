from enum import Enum
from functools import lru_cache
from typing import Union, List, Dict

from scapy.layers.tls.extensions import TLS_Ext_Unknown
from scapy.layers.tls.session import TLSSession, _GenericTLSSessionInheritance
from scapy.main import load_layer

from utils.conversions import flatten
from loguru import logger

# from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.record import TLS, TLSChangeCipherSpec, TLSApplicationData
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

# _TLSHandshake is protected, but we need to perform an instance check on this class
# noinspection PyProtectedMember
from scapy.layers.tls.handshake import _TLSHandshake
from scapy.packet import NoPayload, Raw

# on a per-record basis, the default behavior can not distinguish between TLS12 and TLS13
# thus we need to define TLS13 classes to be used manually
TLS13_HANDSHAKES = {
    1: TLS13ClientHello,
    2: TLS13ServerHello,
    4: TLS13NewSessionTicket,
    5: TLS13EndOfEarlyData,
    11: TLS13Certificate,
    13: TLS13CertificateRequest,
    24: TLS13KeyUpdate,
    # 2: TLS13HelloRetryRequest,
    # later: if TLS1.2 and TLS1.3 differs in record structure, add those here.
}

load_layer("tls")


class ContentType(Enum):
    Unknown = 0
    HelloRetryRequest = 1


class TLSSessionParser:
    """
    A stateless parser for a single TLS stream that processes data in chunks.
    """

    def __init__(self):
        # A buffer to hold data if a chunk doesn't contain a full TLS record.
        self.buffer = b""

    def _get_fixed_message(self, m):
        if isinstance(m, _TLSHandshake):
            cls = TLS13_HANDSHAKES.get(m.msgtype)
            res = cls(m.original) if cls else m
            return res
        elif isinstance(
            m,
            Union[TLSChangeCipherSpec | TLS13ClientHello | TLSApplicationData | Raw],
        ):
            return m
        else:
            raise NotImplementedError

    def parse_chunk(
        self, data: bytes | str, known_content_type: ContentType
    ) -> List[_GenericTLSSessionInheritance]:
        """
        Parses a new chunk of data from the stream.

        Args:
            data: The raw bytes (or hex string) of the new data chunk.
            known_content_type: may indicate what we are parsing (e.g. HelloRetryRequest).
                with the generic TLS() call, scapy 2.6.1 only returns a raw object

        Returns:
            A list of parsed Scapy TLS message objects from this chunk.
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)

        # Add the new data to our internal buffer
        self.buffer += data
        parsed_in_chunk = []

        # Keep parsing while there's data in the buffer
        while self.buffer:
            # we need to do this once anyway to strip the record/message prefix
            record = TLS(self.buffer)

            # if we know the content type, we use the request from the first parsed attempt to strip the preamble
            # the original bytes without the preamble are parsed as the content type
            if known_content_type == ContentType.HelloRetryRequest:
                record.msg[0] = TLS13HelloRetryRequest(record.msg[0].original)
                # payload = record.msg[0].payload

            # reset the content type in case we have another iteration (only designed for the first message currently)
            known_content_type = ContentType.Unknown

            # If Scapy couldn't parse a full record, the .msg list will be empty.
            # We break the loop and wait for more data.
            if not record.msg:
                break

            # at least for the TLS13NewSessionTicket we need to tell scapy that it is TLS13
            parsed_fixed_classes = [self._get_fixed_message(m) for m in record.msg]

            # Add the successfully parsed messages to our results
            parsed_in_chunk.extend(parsed_fixed_classes)

            # The unparsed part of the buffer is in the payload. This becomes
            # our new buffer for the next iteration of the loop.
            if isinstance(record.payload, NoPayload):
                self.buffer = b""
            else:
                self.buffer = bytes(record.payload)

        return flatten(parsed_in_chunk)


tsp = TLSSessionParser()


@lru_cache
def parse_tls13_cached(
    data: bytes | str, known_content_type: ContentType = ContentType.Unknown
) -> dict:
    res: List[_GenericTLSSessionInheritance] = tsp.parse_chunk(data, known_content_type)
    return _get_parsed_dict(res)


def _get_parsed_dict(
    parsed_list: List[_GenericTLSSessionInheritance],
):

    parse_response = list()
    for parsed in parsed_list:
        parse_response_message = dict()
        logger.debug(f"In handle Handshake with type {type(parsed)}")
        # parse_response_message["message_header"] = parsed.original[
        #     :4
        # ]  # get the first 4 bytes (1 byte message type, 3 bytes message length)
        parse_response_message["transcript"] = parsed.original

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

    return dict(messages=parse_response)


def _format_fields(parsed, of_interest_mapping: dict):
    answer = dict()
    for field in parsed.fields_desc:
        if not field.name in of_interest_mapping.keys():
            logger.warning(
                f"Not including attribute '{field.name}' of {type(parsed)} in response. Would be '{_get_field_value(parsed, field)}'"
            )
            continue
        value = _get_field_value(parsed, field)
        if isinstance(value, bytes):
            assert (
                value in parsed.original
            ), f"constructed value {value} not found in original {parsed.original}"
        answer[of_interest_mapping[field.name]] = value
    return answer


def _get_field_value(parsed, field) -> bytes | List[dict]:
    logger.debug(f"value of {field.name}: {getattr(parsed, field.name)}")
    value = getattr(parsed, field.name)
    return _format_field_value(field, value)


def _format_field_value(field, value):
    if isinstance(value, bytes):
        return value
    elif isinstance(value, int):
        return field.struct.pack(value)
    elif isinstance(value, list):
        if all(isinstance(item, int) for item in value):
            return b"".join(map(lambda x: field.struct.pack(x), value))
        if all(isinstance(item, TLS_Ext_Unknown) for item in value):
            # this makes the extensions being returned as the original string instead of the object
            # return b"".join(map(lambda x: x.original, value))
            return _format_extensions(field, value)

    raise NotImplementedError(
        f"Not implemented return type: {type(value)}. Need conversion to bytes"
    )


def __format_extension_name(name: str):
    return name.lower().replace("tls extension - ", "").replace(" ", "_")


def __format_extension(item):
    return dict(
        extension_type=__format_extension_name(item.name),
        # the original data contains 0000 (type server name) 0019 (length) and then the content
        extension_data=item.original,
    )


def _format_extensions(field, value):
    return [__format_extension(item) for item in value]
