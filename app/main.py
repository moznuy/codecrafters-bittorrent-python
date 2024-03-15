from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from typing import Any


# import bencodepy - available if you need it!
# import requests - available if you need it!


def _decode_bencode(bencoded_value: bytes) -> tuple[Any, bytes]:
    byte = bencoded_value[0]
    if chr(byte).isdigit():
        index = bencoded_value.find(b":")
        if index == -1:
            raise ValueError("Invalid encoded string")
        length = int(bencoded_value[:index])
        raw = bencoded_value[index + 1 : index + 1 + length]
        if length != len(raw):
            raise ValueError("Invalid encoded string: length does not match")
        return raw, bencoded_value[index + 1 + length :]

    elif bencoded_value.startswith(b"i"):
        index = bencoded_value.index(b"e")
        if index == -1:
            raise ValueError("Invalid encoded integer")
        raw = bencoded_value[1:index]
        if raw == b"-0":
            raise ValueError("Invalid encoded integer -0")
        if raw.startswith(b"-0") or (raw.startswith(b"0") and raw != b"0"):
            raise ValueError("Invalid encoded integer leading 0s")
        return int(raw), bencoded_value[index + 1 :]

    elif bencoded_value.startswith(b"l"):
        res_l: list[Any] = []
        bencoded_value = bencoded_value[1:]
        while bencoded_value:
            if bencoded_value.startswith(b"e"):
                return res_l, bencoded_value[1:]
            if not bencoded_value:
                raise ValueError("Invalid encoded list")
            value, bencoded_value = _decode_bencode(bencoded_value)
            res_l.append(value)

    elif bencoded_value.startswith(b"d"):
        res_d: list[tuple[str, Any]] = []
        bencoded_value = bencoded_value[1:]
        while bencoded_value:
            if bencoded_value.startswith(b"e"):
                return dict(res_d), bencoded_value[1:]
            if not bencoded_value:
                raise ValueError("Invalid encoded dict")
            key, bencoded_value = _decode_bencode(bencoded_value)
            value, bencoded_value = _decode_bencode(bencoded_value)
            if not isinstance(key, bytes):
                raise ValueError("Invalid encoded dict: keys must be strings")
            key_s = key.decode()  # TODO: not to do this; needed for json.dumps
            if res_d and key_s < res_d[-1][0]:
                raise ValueError("Invalid encoded dict: keys must sorted")
            res_d.append((key_s, value))

    else:
        raise NotImplementedError("Only strings are supported at the moment")


def decode_bencode(bencoded_value: bytes):
    result, rest = _decode_bencode(bencoded_value)
    if rest:
        raise ValueError("data after the end")
    return result


def encode_bencode(value: Any) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, list):
        return b"l" + b"".join(encode_bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        return (
            b"d"
            + b"".join(
                encode_bencode(key) + encode_bencode(value[key])
                for key in sorted(value)
            )
            + b"e"
        )
    raise NotImplementedError

@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class TorrentFileInfo:
    length: int
    path: list[bytes]


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class TorrentInfo:
    name: str
    piece_length: int
    pieces: list[str]
    length: int | None = None
    files: list[dict] | None = None


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class TorrentFile:
    announce: str
    info: TorrentInfo
    sha1: bytes


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def parse_file(filename: str):
    with open(filename, "rb") as f:
        data = f.read()

    payload = decode_bencode(data)
    info_raw = payload["info"]
    assert len(info_raw["pieces"]) % 20 == 0

    assert ("length" in info_raw) != ("files" in info_raw)

    if "length" in info_raw:
        info = TorrentInfo(
            name=info_raw["name"].decode(),
            piece_length=info_raw["piece length"],
            pieces=list(chunks(info_raw["pieces"], 20)),
            length=info_raw["length"],
        )
    else:
        raise NotImplementedError

    r = encode_bencode(payload["info"])
    sha1 = hashlib.sha1(r).digest()
    return TorrentFile(announce=payload["announce"].decode(), info=info, sha1=sha1)


def print_torrent(torrent: TorrentFile):
    print(f"Tracker URL: {torrent.announce}")
    print(f"Length: {torrent.info.length}")
    print(f"Info Hash: {torrent.sha1.hex()}")


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
    elif command == "info":
        filename = sys.argv[2]
        torrent = parse_file(filename)
        print_torrent(torrent)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
