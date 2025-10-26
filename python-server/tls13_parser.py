from enum import Enum
from functools import lru_cache
from typing import Union, List

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
            # Tell Scapy to use our persistent session object to continue the dissection.
            # Scapy will update self.session internally.

            # if known_content_type == ContentType.HelloRetryRequest:
            #     record = TLS13HelloRetryRequest(self.buffer)
            # elif known_content_type == ContentType.Unknown:
            #     record = TLS(self.buffer)
            # else:
            #     raise NotImplementedError(
            #         "Not implemented ContentType hint. Try generic API."
            #     )

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
) -> List[_GenericTLSSessionInheritance]:
    res = tsp.parse_chunk(data, known_content_type)
    return res


# if __name__ == '__main__':
#     raw_hex_new_session_ticket = "1603030039" + "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"
#     rec, msgs = parse_tls13(bytes.fromhex(raw_hex_new_session_ticket))
#     print(msgs)
