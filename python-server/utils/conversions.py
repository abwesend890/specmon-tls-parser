def int_to_bytes(n: int) -> bytes:
    """Converts an integer to bytes via hex string manipulation."""
    if n < 0:
        raise ValueError("This method only supports non-negative integers.")
    hex_string = hex(n)[2:]
    if len(hex_string) % 2:
        hex_string = "0" + hex_string
    return bytes.fromhex(hex_string)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")
