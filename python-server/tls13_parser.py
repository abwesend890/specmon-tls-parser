from functools import lru_cache
from typing import Union

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

from scapy.layers.tls.all import TLSSession

global recent_session
recent_session = None


@lru_cache
def parse_tls13(data: bytes | str):
    if isinstance(data, bytes):
        pass
    if isinstance(data, str):
        data = bytes.fromhex(data)

    global recent_session

    if recent_session is not None:
        record = TLS(
            data,
            tls_session=recent_session,
        )
    else:
        record: TLS = TLS(data)
    recent_session = record.tls_session

    parsed = []

    for m in record.msg:
        if isinstance(m, _TLSHandshake):
            cls = TLS13_HANDSHAKES.get(m.msgtype)
            parsed.append(cls(m.original) if cls else m)
        elif isinstance(
            m, Union[TLSChangeCipherSpec | TLS13ClientHello | TLSApplicationData | Raw]
        ):
            parsed.append(m)
        else:
            raise NotImplementedError
            # parsed.append(m)
    if not isinstance(record.payload, NoPayload):
        parsed.append(parse_tls13(record.payload.original))
    parsed = flatten(parsed)
    return parsed


# if __name__ == '__main__':
#     raw_hex_new_session_ticket = "1603030039" + "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"
#     rec, msgs = parse_tls13(bytes.fromhex(raw_hex_new_session_ticket))
#     print(msgs)
