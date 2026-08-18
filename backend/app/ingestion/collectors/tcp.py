from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator

from app.domain.events.models import RawEvent
from app.ingestion.collectors.base import Collector
from app.ingestion.receivers.tcp import TCPReceiver

logger = logging.getLogger(__name__)


class TCPCollector(Collector):
    """Asynchronous newline-delimited TCP security-event collector."""

    _READ_CHUNK_SIZE = 4096

    def __init__(
        self,
        *,
        name: str,
        host: str,
        port: int,
        source: str,
        max_line_bytes: int = 64 * 1024,
        queue_size: int = 10_000,
    ) -> None:
        super().__init__(name)

        normalized_host = host.strip()
        normalized_source = source.strip()

        if not normalized_host:
            raise ValueError("host must not be empty")

        if not 1 <= port <= 65_535:
            raise ValueError("port must be between 1 and 65535")

        if not normalized_source:
            raise ValueError("source must not be empty")

        if max_line_bytes <= 0:
            raise ValueError("max_line_bytes must be greater than zero")

        if queue_size <= 0:
            raise ValueError("queue_size must be greater than zero")

        self.host = normalized_host
        self.port = port
        self.source = normalized_source
        self.max_line_bytes = max_line_bytes

        self._receiver = TCPReceiver()

        self._events: asyncio.Queue[RawEvent] = asyncio.Queue(
            maxsize=queue_size,
        )

        self._server: asyncio.AbstractServer | None = None
        self._clients: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        """Start the TCP listener."""
        if self.running:
            raise RuntimeError(f"collector already running: {self.name}")

        await super().start()

        try:
            server = await asyncio.start_server(
                self._handle_client,
                host=self.host,
                port=self.port,
                limit=self.max_line_bytes,
            )
        except Exception:
            await super().stop()
            raise

        self._server = server

        sockets = server.sockets or []

        addresses = tuple(str(socket.getsockname()) for socket in sockets)

        logger.info(
            "TCP collector started "
            "(name=%s, source=%s, addresses=%s, "
            "max_line_bytes=%d, queue_size=%d).",
            self.name,
            self.source,
            addresses,
            self.max_line_bytes,
            self._events.maxsize,
        )

    async def stop(self) -> None:
        """Stop the TCP listener and all active client handlers."""
        server = self._server
        self._server = None

        if server is not None:
            server.close()

            try:
                await server.wait_closed()
            except Exception:
                logger.exception(
                    "Failed to close TCP server (collector=%s).",
                    self.name,
                )

        client_tasks = tuple(self._clients)

        for task in client_tasks:
            task.cancel()

        if client_tasks:
            await asyncio.gather(
                *client_tasks,
                return_exceptions=True,
            )

        self._clients.clear()

        await super().stop()

        logger.info(
            "TCP collector stopped (name=%s).",
            self.name,
        )

    async def collect(self) -> AsyncIterator[RawEvent]:
        """Yield raw events produced by connected TCP clients."""
        while self.running:
            event = await self._events.get()

            try:
                yield event
            finally:
                self._events.task_done()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Receive newline-delimited payloads from one TCP client."""
        task = asyncio.current_task()

        if task is not None:
            self._clients.add(task)

        peer = writer.get_extra_info("peername")
        source = self._build_source(peer)

        logger.debug(
            "TCP client connected (collector=%s, peer=%s).",
            self.name,
            peer,
        )

        try:
            while self.running:
                try:
                    payload = await reader.readline()

                except asyncio.LimitOverrunError:
                    logger.warning(
                        "Dropping oversized TCP payload (collector=%s, peer=%s, limit=%d).",
                        self.name,
                        peer,
                        self.max_line_bytes,
                    )

                    await self._drain_until_newline(reader)
                    continue

                if not payload:
                    break

                if len(payload) > self.max_line_bytes:
                    logger.warning(
                        "Dropping oversized TCP payload "
                        "(collector=%s, peer=%s, bytes=%d, "
                        "limit=%d).",
                        self.name,
                        peer,
                        len(payload),
                        self.max_line_bytes,
                    )
                    continue

                text = payload.decode(
                    "utf-8",
                    errors="replace",
                ).rstrip("\r\n")

                if not text:
                    continue

                event = self._receiver.receive(
                    text,
                    source=source,
                )

                await self._events.put(event)

                logger.debug(
                    "TCP event queued (collector=%s, peer=%s, queue_depth=%d).",
                    self.name,
                    peer,
                    self._events.qsize(),
                )

        except asyncio.CancelledError:
            raise

        except ConnectionResetError:
            logger.debug(
                "TCP client disconnected unexpectedly (collector=%s, peer=%s).",
                self.name,
                peer,
            )

        except asyncio.IncompleteReadError:
            logger.debug(
                "TCP client closed connection during read (collector=%s, peer=%s).",
                self.name,
                peer,
            )

        except Exception:
            logger.exception(
                "TCP client handling failed (collector=%s, peer=%s).",
                self.name,
                peer,
            )

        finally:
            await self._close_writer(
                writer,
                collector_name=self.name,
                peer=peer,
            )

            if task is not None:
                self._clients.discard(task)

            logger.debug(
                "TCP client handler closed (collector=%s, peer=%s).",
                self.name,
                peer,
            )

    @classmethod
    async def _drain_until_newline(
        cls,
        reader: asyncio.StreamReader,
    ) -> None:
        """Discard input until the next newline delimiter."""
        while True:
            chunk = await reader.read(cls._READ_CHUNK_SIZE)

            if not chunk:
                return

            if b"\n" in chunk:
                return

    @staticmethod
    async def _close_writer(
        writer: asyncio.StreamWriter,
        *,
        collector_name: str,
        peer: object,
    ) -> None:
        """Close a TCP client writer safely."""
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            logger.debug(
                "TCP writer close failed (collector=%s, peer=%s).",
                collector_name,
                peer,
                exc_info=True,
            )

    def _build_source(
        self,
        peer: object,
    ) -> str:
        """Build a stable event source identifier."""
        if isinstance(peer, tuple) and peer:
            host = str(peer[0]).strip()

            if host:
                return f"{self.source}:{host}"

        return self.source
