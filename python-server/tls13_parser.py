from typing import Union

from loguru import logger

# from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.record import TLS, TLSChangeCipherSpec
from scapy.layers.tls.handshake import (
    TLS13ClientHello,
    TLS13ServerHello,
    TLS13NewSessionTicket,
    TLS13Certificate,
    TLS13CertificateRequest,
    TLS13KeyUpdate,
    TLS13EndOfEarlyData,
)

# _TLSHandshake is protected, but we need to perform an instance check on this class
# noinspection PyProtectedMember
from scapy.layers.tls.handshake import _TLSHandshake

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
    # later: if TLS1.2 and TLS1.3 differs in record structure, add those here.
}


def parse_tls13(data: bytes | str):
    if isinstance(data, bytes):
        pass
    if isinstance(data, str):
        data = bytes.fromhex(data)

    record: TLS = TLS(data)
    parsed = []
    for m in record.msg:
        if isinstance(m, _TLSHandshake):
            cls = TLS13_HANDSHAKES.get(m.msgtype)
            parsed.append(cls(m.original) if cls else m)
        elif isinstance(m, Union[TLSChangeCipherSpec | TLS13ClientHello]):
            parsed.append(m)
        else:
            raise NotImplementedError
            # parsed.append(m)
    return parsed


# if __name__ == '__main__':
#     raw_hex_new_session_ticket = "1603030039" + "040000350000012cb2e84fd00800000000000000000020078ce471076e6fcf8a8cbce7d3ef876bd01c1caeccded1fa1e722ffe3946821b0000"
#     rec, msgs = parse_tls13(bytes.fromhex(raw_hex_new_session_ticket))
#     print(msgs)
