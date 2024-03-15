from __future__ import annotations

import collections
import dataclasses
import functools
import hashlib
import json
import math
import os.path
import random
import socket
import string
import struct
import sys
import urllib.request
import urllib.parse
from typing import Any


IGNORE_SORT_IN_DECODE = True


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
            if not IGNORE_SORT_IN_DECODE:
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
    pieces: list[bytes]
    length: int | None = None
    files: list[dict] | None = None


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class TorrentFile:
    announce: str
    info: TorrentInfo
    sha1: bytes


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class PeerRaw:
    ip: bytes
    port: bytes


@dataclasses.dataclass(slots=True, frozen=True, kw_only=True)
class Peer:
    ip: str
    port: int


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


def torrent_print(torrent: TorrentFile):
    print(f"Tracker URL: {torrent.announce}")
    print(f"Length: {torrent.info.length}")
    print(f"Info Hash: {torrent.sha1.hex()}")
    print(f"Piece Length: {torrent.info.piece_length}")
    print(f"Piece Hashes:")
    for piece in torrent.info.pieces:
        print(piece.hex())


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return "".join(random.choice(chars) for _ in range(size))


PEER_ID = id_generator(20)
PORT = 6881


def get_peers(torrent: TorrentFile):
    query = urllib.parse.urlencode(
        {
            "info_hash": torrent.sha1,
            "peer_id": PEER_ID,
            "port": PORT,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent.info.length,
            "compact": 1,
        }
    )
    parsed = urllib.parse.urlparse(torrent.announce)
    # print(parsed)
    # parsed.query = query
    url = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment,
        )
    )
    # print(url)
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as f:
        resp = f.read()
    payload = decode_bencode(resp)
    interval = payload["interval"]
    peers_raw = list(
        PeerRaw(ip=ip, port=port)
        for ip, port in struct.iter_unpack("<4sH", payload["peers"])
    )
    peers = [
        Peer(ip=socket.inet_ntoa(peer_raw.ip), port=socket.ntohs(peer_raw.port))
        for peer_raw in peers_raw
    ]
    return peers


def handshake(torrent: TorrentFile, peer: str):
    split = peer.split(":", 1)
    assert len(split) == 2
    ip = split[0]
    port = int(split[1])

    conn = socket.create_connection((ip, port), timeout=10)
    handshake_msg = craft_handshake(torrent)
    conn.sendall(handshake_msg)
    payload = conn.recv(4096)

    peer_id = payload[48 : 48 + 20]
    print(f"Peer ID: {peer_id.hex()}")


def craft_handshake(torrent: TorrentFile):
    protocol = b"BitTorrent protocol"
    handshake_msg = b""
    handshake_msg += len(protocol).to_bytes(1, byteorder="big")  # Len str
    handshake_msg += protocol
    handshake_msg += b"\x00" * 8  # Reserved
    assert len(torrent.sha1) == 20
    handshake_msg += torrent.sha1
    peer_id = PEER_ID.encode()
    assert len(peer_id) == 20
    handshake_msg += peer_id
    return handshake_msg


def craft_interested():
    interested = b""
    data = (2).to_bytes(1, "big", signed=False)
    interested += len(data).to_bytes(4, "big", signed=False)
    interested += data
    assert len(interested) == 5
    return interested


def craft_request(piece_index: int, offset: int, length: int) -> bytes:
    data = b""
    data += (6).to_bytes(1, "big", signed=False)  # msg id
    data += piece_index.to_bytes(4, "big", signed=False)  # index
    data += offset.to_bytes(4, "big", signed=False)  # begin
    data += length.to_bytes(4, "big", signed=False)  # length
    request = b""
    request += len(data).to_bytes(4, "big", signed=False)
    request += data
    return request


def craft_requests(pc: PeerConnection):
    data = b""
    piece_count = math.ceil(pc.length / pc.piece_length)
    last_piece_index = piece_count - 1
    if pc.length % pc.piece_length == 0:
        last_piece_length = pc.piece_length
    else:
        last_piece_length = pc.length % pc.piece_length

    for piece_index in pc.pieces_needed:
        piece_length = (
            pc.piece_length if piece_index != last_piece_index else last_piece_length
        )
        for offset in range(0, piece_length, 16 * 1024):
            length = min(16 * 1024, piece_length - offset)
            assert length > 0
            data += craft_request(piece_index, offset, length)
    return data


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class PieceData:
    index: int
    begin: int
    block: bytes


@dataclasses.dataclass(kw_only=True, slots=True)
class PeerConnection:
    send_data: bytes
    recv_data: bytes
    length: int
    piece_length: int

    # TODO: tmp
    to: str

    pieces_needed: list[int] = dataclasses.field(default_factory=list)
    pieces_data: list[PieceData] = dataclasses.field(default_factory=list)
    pieces_written: dict[int, set[int]] = dataclasses.field(
        default_factory=functools.partial(collections.defaultdict, set)
    )

    handshake_recv: bool = False
    bitfield: bytes | None = None
    sent_interested: bool = False
    chocked_local: bool = True
    request_sent: bool = False
    try_write: bool = False


def download_piece(torrent: TorrentFile, to: str, piece_no: int):
    peers = get_peers(torrent)
    assert peers
    peer: Peer = random.choice(peers)

    conn = socket.create_connection((peer.ip, peer.port), timeout=10)
    handshake_msg = craft_handshake(torrent)
    pc = PeerConnection(
        send_data=handshake_msg,
        recv_data=b"",
        to=to,
        length=torrent.info.length,
        piece_length=torrent.info.piece_length,
        pieces_needed=[piece_no],
    )
    while True:
        if pc.send_data:
            conn.sendall(pc.send_data)
            pc.send_data = b""

        chunk = conn.recv(4096)
        if not conn:
            raise RuntimeError("Connection closed")
        pc.recv_data += chunk
        parse_peer_data(pc)


def bitfield_handler(pc: PeerConnection, data: bytes):
    pc.bitfield = data
    # print("Bitfield:", pc.bitfield)


def unchoke_handler(pc: PeerConnection, data: bytes):
    pc.chocked_local = False
    # print("Unchocked local")


def piece_handler(pc: PeerConnection, data: bytes):
    if len(data) < 8:
        print("WARNING: piece block to small, discard")
        return
    index, begin = struct.unpack_from(">II", data)
    block = data[8:]
    pd = PieceData(index=index, begin=begin, block=block)
    pc.pieces_data.append(pd)
    # print("Piece", pd)
    pc.try_write = True


PACKET_MAPPING = {
    1: unchoke_handler,
    5: bitfield_handler,
    7: piece_handler,
}


def try_write(pc: PeerConnection):
    # TODO: same code
    piece_count = math.ceil(pc.length / pc.piece_length)
    last_piece_index = piece_count - 1

    if pc.length % pc.piece_length == 0:
        last_piece_length = pc.piece_length
    else:
        last_piece_length = pc.length % pc.piece_length

    piece_fragment_count = math.ceil(pc.piece_length / (16 * 1024))
    # if last_piece_length == pc.piece_length:
    #     last_piece_fragment_count = piece_fragment_count
    # else:
    last_piece_fragment_count = math.ceil(last_piece_length / (16 * 1024))
    normal_set = set(range(piece_fragment_count))
    last_set = set(range(last_piece_fragment_count))

    while pc.pieces_data:
        piece = pc.pieces_data.pop()
        # TODO: check length

        file_size = (
            pc.piece_length if piece.index != last_piece_index else last_piece_length
        )
        if not os.path.exists(pc.to):
            with open(pc.to, "wb") as _:
                pass
            os.truncate(pc.to, file_size)

        with open(pc.to, "rb+") as file:
            file.seek(piece.begin, os.SEEK_SET)
            file.write(piece.block)

        # TODO: instead of set_of_indexes do a proper segment tree
        pc.pieces_written[piece.index].add(piece.begin // (16 * 1024))
        if piece.index == last_piece_index:
            _set = last_set
        else:
            _set = normal_set
        if _set == pc.pieces_written[piece.index]:
            # TODO: remove pc.to
            print(f"Piece {piece.index} downloaded to {pc.to}.")
            # TODO: remove later
            exit(0)


def parse_peer_data(pc: PeerConnection):
    assert pc.recv_data

    while True:
        if pc.bitfield and not pc.sent_interested:
            pc.send_data += craft_interested()
            pc.sent_interested = True
            # print("Sent interested")

        if not pc.chocked_local and not pc.request_sent:
            pc.send_data += craft_requests(pc)
            pc.request_sent = True
            # print("Sent requests")

        if not pc.handshake_recv:
            if len(pc.recv_data) < 68:  # Not enough for handshake
                return
            peer_handshake, pc.recv_data = pc.recv_data[:68], pc.recv_data[68:]
            pc.handshake_recv = True

        if pc.handshake_recv:
            if len(pc.recv_data) < 4:  # Not enough for length
                return
            (length,) = struct.unpack_from(">I", pc.recv_data)
            if len(pc.recv_data) < 4 + length:  # Not enough for whole packet
                return
            packet, pc.recv_data = (
                pc.recv_data[4 : 4 + length],
                pc.recv_data[4 + length :],
            )
            message_id = packet[0]
            handler = PACKET_MAPPING.get(message_id)
            if handler is None:
                print("Unknown message id", message_id)
                continue
            handler(pc, packet[1:])
            try_write(pc)
            continue

    raise NotImplementedError


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
        torrent_print(torrent)
    elif command == "peers":
        filename = sys.argv[2]
        torrent = parse_file(filename)
        peers = get_peers(torrent)
        for peer in peers:
            print(f"{peer.ip}:{peer.port}")
    elif command == "handshake":
        filename = sys.argv[2]
        torrent = parse_file(filename)
        peer = sys.argv[3]
        handshake(torrent, peer)
    elif command == "download_piece":
        to = sys.argv[3]
        filename = sys.argv[4]
        piece_no = sys.argv[5]
        torrent = parse_file(filename)
        download_piece(torrent, to, int(piece_no))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
