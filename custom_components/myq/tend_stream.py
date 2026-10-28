"""Expose a TC camera's Tend video as a loopback H.264 source for HA stream."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import Awaitable, Callable

from .tend import (
    CxsConnection,
    TendCamera,
    TendStreamError,
    VideoOffer,
    VideoTransport,
    parse_cameras,
    request_video,
)

_LOGGER = logging.getLogger(__name__)
_IDLE_SECONDS = 60


def _nals(data: bytes) -> list[tuple[int, bytes]]:
    """Return the H.264 NAL units in one Annex B access unit."""
    starts: list[tuple[int, int]] = []
    index = 0
    while index + 3 < len(data):
        start = 0
        if data[index : index + 3] == b"\x00\x00\x01":
            start = 3
        elif data[index : index + 4] == b"\x00\x00\x00\x01":
            start = 4
        if start:
            starts.append((index, start))
            index += start
        else:
            index += 1
    units: list[tuple[int, bytes]] = []
    for position, (start, prefix) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(data)
        if end > start + prefix:
            units.append((data[start + prefix] & 0x1F, data[start:end]))
    return units


class _Viewer:
    def __init__(self) -> None:
        self.frames: asyncio.Queue[bytes] = asyncio.Queue(maxsize=60)
        self.ready = False

    def put(self, frame: bytes) -> None:
        if self.frames.full():
            self.frames.get_nowait()
        self.frames.put_nowait(frame)


class TendLiveStream:
    """Share one Tend session among Home Assistant stream consumers."""

    def __init__(self, serial_number: str, token_supplier: Callable[[], Awaitable[str]]) -> None:
        self.serial_number = serial_number
        self._token_supplier = token_supplier
        self._path = "/" + secrets.token_urlsafe(24) + ".h264"
        self._server: asyncio.Server | None = None
        self._server_lock = asyncio.Lock()
        self._connection: CxsConnection | None = None
        self._transport: VideoTransport | None = None
        self._camera: TendCamera | None = None
        self._offer: VideoOffer | None = None
        self._lock = asyncio.Lock()
        self._viewers: set[_Viewer] = set()
        self._idle_task: asyncio.Task[None] | None = None
        self._sps: bytes | None = None
        self._pps: bytes | None = None
        self._closed = False

    async def source_url(self) -> str:
        """Return an unguessable loopback URL for HA's FFmpeg stream reader."""
        if self._closed:
            raise TendStreamError("Tend camera stream is closed")
        async with self._server_lock:
            if self._closed:
                raise TendStreamError("Tend camera stream is closed")
            if self._server is None:
                self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        address = self._server.sockets[0].getsockname()
        return f"http://127.0.0.1:{address[1]}{self._path}"

    async def _open(self) -> None:
        async with self._lock:
            if self._transport is not None:
                return
            connection = CxsConnection()
            transport: VideoTransport | None = None
            try:
                await connection.login(await self._token_supplier())
                cameras = parse_cameras(connection.properties)
                camera_id = self.serial_number.rsplit("-", 1)[-1]
                camera = next(
                    (item for item in cameras if item.device_id in (camera_id, self.serial_number)),
                    None,
                )
                if camera is None:
                    raise TendStreamError("TC camera was not listed by Tend signaling")
                last_error: TendStreamError | None = None
                for attempt in range(2):
                    offer = await request_video(connection, camera)
                    transport = VideoTransport(camera, offer, self._on_frame)
                    try:
                        await transport.punch(8)
                    except TendStreamError as error:
                        last_error = error
                        transport.close()
                        transport = None
                        if attempt == 0:
                            await asyncio.sleep(4)
                        continue
                    await connection.command(
                        f"start-video-receive|{camera.device_id}|9|",
                        camera.destination,
                        offer.correlation,
                    )
                    await connection.command(
                        f"modify-device|{camera.device_id}|QTY=3+FPS=20+SIZE=0+SAVE=0|",
                        camera.destination,
                    )
                    self._connection = connection
                    self._transport = transport
                    self._camera = camera
                    self._offer = offer
                    _LOGGER.debug("Connected Tend TC camera video")
                    return
                raise last_error or TendStreamError("TC camera media connection failed")
            except (OSError, TimeoutError, ValueError) as error:
                raise TendStreamError("TC camera media connection failed") from error
            finally:
                if self._transport is None:
                    if transport is not None:
                        transport.close()
                    connection.close()

    def _on_frame(self, frame: bytes) -> None:
        units = _nals(frame)
        types = {nal_type for nal_type, _ in units}
        if not types:
            return
        for nal_type, nal in units:
            if nal_type == 7:
                self._sps = nal
            elif nal_type == 8:
                self._pps = nal
        for viewer in self._viewers:
            if not viewer.ready:
                if 5 not in types or self._sps is None or self._pps is None:
                    continue
                if 7 not in types:
                    viewer.put(self._sps)
                if 8 not in types:
                    viewer.put(self._pps)
                viewer.ready = True
            viewer.put(frame)

    async def _subscribe(self) -> _Viewer:
        if self._closed:
            raise TendStreamError("Tend camera stream is closed")
        if self._idle_task is not None:
            self._idle_task.cancel()
            self._idle_task = None
        await self._open()
        if bool(self._closed):
            await self._close_session()
            raise TendStreamError("Tend camera stream is closed")
        viewer = _Viewer()
        self._viewers.add(viewer)
        return viewer

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        viewer: _Viewer | None = None
        stalled = False
        try:
            request = await asyncio.wait_for(reader.readline(), 5)
            if request != f"GET {self._path} HTTP/1.1\r\n".encode() and request != (
                f"GET {self._path} HTTP/1.0\r\n".encode()
            ):
                writer.write(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            while await asyncio.wait_for(reader.readline(), 5) not in (b"\r\n", b"\n", b""):
                pass
            writer.write(
                b"HTTP/1.0 200 OK\r\nContent-Type: video/h264\r\nCache-Control: no-store\r\n\r\n"
            )
            await writer.drain()
            viewer = await self._subscribe()
            disconnect = asyncio.create_task(reader.read(1))
            try:
                while not disconnect.done():
                    next_frame = asyncio.create_task(viewer.frames.get())
                    try:
                        done, _ = await asyncio.wait(
                            (disconnect, next_frame),
                            timeout=30,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if not done:
                            raise TimeoutError("TC camera stopped sending video")
                        if disconnect in done:
                            break
                        frame = next_frame.result()
                        if not frame:
                            break
                        writer.write(frame)
                        await writer.drain()
                    finally:
                        next_frame.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await next_frame
            finally:
                disconnect.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await disconnect
        except (TimeoutError, TendStreamError) as error:
            _LOGGER.warning("TC camera live video unavailable: %s", error)
            stalled = isinstance(error, TimeoutError)
        except (ConnectionError, OSError) as error:
            _LOGGER.debug("Tend TC live stream client ended: %s", error)
        finally:
            if viewer is not None:
                self._viewers.discard(viewer)
                if not self._viewers and not self._closed:
                    if stalled:
                        await self._close_session()
                    else:
                        self._idle_task = asyncio.create_task(self._idle_close())
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def _idle_close(self) -> None:
        try:
            await asyncio.sleep(_IDLE_SECONDS)
        except asyncio.CancelledError:
            return
        self._idle_task = None
        if not self._viewers:
            await self._close_session()

    async def _close_session(self) -> None:
        async with self._lock:
            connection = self._connection
            camera = self._camera
            offer = self._offer
            self._connection = None
            self._camera = None
            self._offer = None
            if connection is not None and camera is not None and offer is not None:
                with contextlib.suppress(OSError, TendStreamError):
                    await connection.command(
                        f"stop-video-receive|{camera.device_id}|9|",
                        camera.destination,
                        offer.correlation,
                    )
            if self._transport is not None:
                self._transport.close()
                self._transport = None
            if connection is not None:
                connection.close()
            self._sps = None
            self._pps = None

    async def close(self) -> None:
        """Stop accepting viewers and close the Tend session."""
        self._closed = True
        if self._idle_task is not None:
            self._idle_task.cancel()
        for viewer in self._viewers:
            viewer.put(b"")
        async with self._server_lock:
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
        await self._close_session()
