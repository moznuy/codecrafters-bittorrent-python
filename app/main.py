import json
import sys
from typing import Any


# import bencodepy - available if you need it!
# import requests - available if you need it!


def _decode_bencode(bencoded_value: bytes) -> tuple[Any, int]:
    byte = bencoded_value[0]
    if chr(byte).isdigit():
        index = bencoded_value.find(b":")
        if index == -1:
            raise ValueError("Invalid encoded string")
        length = int(bencoded_value[:index])
        raw = bencoded_value[index + 1:index+1+length].decode()
        if length != len(raw):
            raise ValueError("Invalid encoded string: length does not match")
        return raw, bencoded_value[index+1+length:]

    elif bencoded_value.startswith(b'i'):
        index = bencoded_value.index(b'e')
        if index == -1:
            raise ValueError("Invalid encoded integer")
        raw = bencoded_value[1:index]
        if raw == b'-0':
            raise ValueError("Invalid encoded integer -0")
        if raw.startswith(b'-0') or (raw.startswith(b'0') and raw != b'0'):
            raise ValueError("Invalid encoded integer leading 0s")
        return int(raw), bencoded_value[index + 1:]

    elif bencoded_value.startswith(b'l'):
        res = []
        bencoded_value = bencoded_value[1:]
        while bencoded_value:
            if bencoded_value.startswith(b'e'):
                return res, bencoded_value[1:]
            if not bencoded_value:
                raise ValueError("Invalid encoded list")
            value, bencoded_value = _decode_bencode(bencoded_value)
            res.append(value)


    else:
        raise NotImplementedError("Only strings are supported at the moment")


def decode_bencode(bencoded_value: bytes):
    result, rest = _decode_bencode(bencoded_value)
    if rest:
        raise ValueError("data after the end")
    return result

def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        value = decode_bencode(bencoded_value)
        print(json.dumps(value, default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
