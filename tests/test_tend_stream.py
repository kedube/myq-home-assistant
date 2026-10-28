"""Protocol and local stream checks for TC cameras."""

from __future__ import annotations

import asyncio
import struct
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from custom_components.myq.tend import (
    CxsPacket,
    TendCamera,
    VideoOffer,
    VideoTransport,
    decode_video_payload,
    encode_cxs_packet,
    load_properties,
    parse_cameras,
    parse_peer_packet,
    register_packet,
    store_properties,
)
from custom_components.myq.tend_stream import TendLiveStream, _nals


def test_tend_cxs_and_udp_packets_match_protocol_layout() -> None:
    properties = {"CorrelationID": "LOG-test", "CX_DSTID": "myq:test", "multiline": "one\ntwo"}
    assert load_properties(store_properties(properties)) == properties

    packet = encode_cxs_packet(CxsPacket(519, b"body", source=b"source"))
    assert packet[:2] == b"A\x03"
    assert struct.unpack_from("<H", packet, 13)[0] == 519
    assert struct.unpack_from("<I", packet, 7)[0] == 4
    assert packet[27 + 16 : 27 + 16 + 6] == b"source"

    register = register_packet("myq123", "10.0.1.2", 20000, False)
    assert register[:4] == b"SDNK"
    assert register[7] == 1
    assert struct.unpack_from(">I", register, 16)[0] == len(register) - 20
    assert register[24] == ord("V")
    assert struct.unpack_from(">H", register, 45)[0] == 20000
    assert parse_peer_packet(bytes(109)) == []


def test_tend_video_payload_decrypts_h264_record() -> None:
    frame = b"\x00\x00\x00\x01\x65\x88\x84"
    combined = struct.pack("<I", len(frame)) + frame
    padder = PKCS7(128).padder()
    padded = padder.update(combined) + padder.finalize()
    iv = bytes(range(16))
    key = b"0123456789abcdef"
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    encrypted = iv + encryptor.update(padded) + encryptor.finalize()
    body = b"\x20\x00\x00\x00" + encrypted
    payload = b"w1" + struct.pack("<I", len(body)) + body
    assert decode_video_payload(payload, key.decode()) == [frame]
    assert decode_video_payload(payload, "wrong") == []

    frames: list[bytes] = []
    transport = VideoTransport(
        TendCamera("12345", "12345:aa:bb", key.decode(), "192.168.1.20"),
        VideoOffer("192.168.1.30", 30000, key.decode(), "LOG-test"),
        frames.append,
    )
    rtp = b"\x80\x60" + struct.pack(">HII", 7, 1000, 123) + payload
    transport._handle_media(struct.pack("<II", 1, 0) + rtp[:12])
    transport._handle_media(struct.pack("<II", 1, 1) + rtp[12:])
    transport._handle_media(struct.pack("<II", 2, 0) + b"next")
    assert frames == [frame]
    report = transport._receiver_report()
    assert report is not None
    assert report[:2] == b"\x81\xc9"


def test_tend_camera_selection_data_and_nals() -> None:
    cameras = parse_cameras(
        {
            "device-info-list": "12345:aa:bb,AES=0123456789abcdef+LIP=192.168.1.20\n"
            "67890:cc:dd,AES=abcdef0123456789+LIP=192.168.1.21"
        }
    )
    assert [camera.device_id for camera in cameras] == ["12345", "67890"]
    assert cameras[0].local_ip == "192.168.1.20"
    assert _nals(b"\x00\x00\x01\x67abc\x00\x00\x00\x01\x68def") == [
        (7, b"\x00\x00\x01\x67abc"),
        (8, b"\x00\x00\x00\x01\x68def"),
    ]


async def test_loopback_stream_shares_one_session_and_waits_for_keyframe(
    socket_enabled: None,
) -> None:
    del socket_enabled
    live = TendLiveStream("TC-0005-12345", AsyncMock(return_value="unused"))
    with patch.object(live, "_open", new_callable=AsyncMock) as open_session:
        url = urlsplit(await live.source_url())
        reader, writer = await asyncio.open_connection(url.hostname, url.port)
        writer.write(f"GET {url.path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        assert b"200 OK" in header
        await asyncio.sleep(0)
        live._on_frame(b"\x00\x00\x00\x01\x61p")
        live._on_frame(b"\x00\x00\x00\x01\x67s")
        live._on_frame(b"\x00\x00\x00\x01\x68q")
        assert reader.at_eof() is False
        live._on_frame(b"\x00\x00\x00\x01\x65i")
        assert await asyncio.wait_for(reader.readexactly(6), 2) == b"\x00\x00\x00\x01\x67s"
        assert await asyncio.wait_for(reader.readexactly(6), 2) == b"\x00\x00\x00\x01\x68q"
        assert await asyncio.wait_for(reader.readexactly(6), 2) == b"\x00\x00\x00\x01\x65i"
        open_session.assert_awaited_once()
        await asyncio.wait_for(live.close(), 2)
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()
