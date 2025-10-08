def int_to_bytes(n: int) -> bytes:
    """Converts an integer to bytes via hex string manipulation."""
    if not isinstance(n, int):
        raise ValueError("Input must be an integer")
    if n < 0:
        raise ValueError("This method only supports non-negative integers.")
    hex_string = hex(n)[2:]
    if len(hex_string) % 2:
        hex_string = "0" + hex_string
    return bytes.fromhex(hex_string)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def flatten(nested_list):
    """
    Flattens a nested list.

    For example:
    >>> flatten([1, [2, 3, [4]], 5])
    [1, 2, 3, 4, 5]

    Args:
        nested_list: A list that may contain other lists as elements.

    Returns:
        A single, flattened list.
    """
    flat_list = []
    # Iterate over each element in the input list
    for element in nested_list:
        # Check if the element is a list itself
        if isinstance(element, list):
            # If it's a list, extend the flat_list with the flattened sublist
            flat_list.extend(flatten(element))
        else:
            # If it's not a list, just append it
            flat_list.append(element)
    return flat_list
