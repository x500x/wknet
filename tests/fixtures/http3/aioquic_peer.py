#!/usr/bin/env python3

import argparse
import asyncio
from pathlib import Path
from typing import Dict, List, Tuple

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import FrameType, H3_ALPN, H3Connection, encode_frame
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite


HeaderList = List[Tuple[bytes, bytes]]


class RequestState:
    def __init__(self) -> None:
        self.headers: HeaderList = []
        self.body = bytearray()
        self.trailers: HeaderList = []
        self.responded = False


class PeerQuicLoggerTrace(QuicLoggerTrace):
    def __init__(self, *, is_client: bool, odcid: bytes, log_path: Path) -> None:
        super().__init__(is_client=is_client, odcid=odcid)
        self._log_path = log_path

    def log_event(self, *, category: str, event: str, data: dict) -> None:
        super().log_event(category=category, event=event, data=data)
        if category != "transport" or event != "packet_sent":
            return
        frames = data.get("frames", [])
        frame_types = [str(frame.get("frame_type", "unknown")) for frame in frames]
        header = data.get("header", {})
        packet_type = header.get("packet_type", "unknown")
        packet_number = header.get("packet_number", "unknown")
        with self._log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(
                f"packet_sent type={packet_type} packet_number={packet_number} frames={','.join(frame_types)}\n"
            )


class PeerQuicLogger(QuicLogger):
    def __init__(self, log_path: Path) -> None:
        super().__init__()
        self._log_path = log_path

    def start_trace(self, is_client: bool, odcid: bytes) -> QuicLoggerTrace:
        trace = PeerQuicLoggerTrace(is_client=is_client, odcid=odcid, log_path=self._log_path)
        self._traces.append(trace)
        return trace


class Http3PeerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, scenario: str, log_path: Path, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._scenario = scenario
        self._log_path = log_path
        self._http: H3Connection | None = None
        self._requests: Dict[int, RequestState] = {}

    def _log(self, message: str) -> None:
        with self._log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
            self._log(f"protocol negotiated={event.alpn_protocol}")

        if self._http is None:
            return

        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._handle_headers(http_event)
            elif isinstance(http_event, DataReceived):
                self._handle_data(http_event)

    def _handle_headers(self, event: HeadersReceived) -> None:
        state = self._requests.setdefault(event.stream_id, RequestState())
        if not state.headers:
            state.headers.extend(event.headers)
            self._log(f"request stream={event.stream_id} headers={len(event.headers)}")
        else:
            state.trailers.extend(event.headers)
            self._log(f"request stream={event.stream_id} trailers={len(event.headers)}")

        if event.stream_ended:
            self._respond(event.stream_id, state)

    def _handle_data(self, event: DataReceived) -> None:
        state = self._requests.setdefault(event.stream_id, RequestState())
        state.body.extend(event.data)
        self._log(f"request stream={event.stream_id} body_bytes={len(state.body)}")
        if event.stream_ended:
            self._respond(event.stream_id, state)

    def _respond(self, stream_id: int, state: RequestState) -> None:
        if state.responded or self._http is None:
            return
        state.responded = True

        method = next((value for name, value in state.headers if name == b":method"), b"")
        path = next((value for name, value in state.headers if name == b":path"), b"")
        self._log(
            f"complete stream={stream_id} method={method.decode('ascii', errors='replace')} "
            f"path={path.decode('ascii', errors='replace')} body_bytes={len(state.body)}"
        )

        if self._scenario == "cancel":
            return

        response_body = b"wknet-http3-aioquic"
        if self._scenario == "post-request-body":
            response_body = b"received:" + str(len(state.body)).encode("ascii")
        elif self._scenario == "loss-reorder":
            response_body = b"L" * 3000

        response_headers: HeaderList = [
            (b":status", b"200"),
            (b"server", b"wknet-aioquic-peer"),
            (b"content-length", str(len(response_body)).encode("ascii")),
        ]
        self._http.send_headers(stream_id=stream_id, headers=response_headers, end_stream=False)

        if self._scenario == "head-no-body" or method == b"HEAD":
            self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)
        elif self._scenario == "trailers":
            self._http.send_data(stream_id=stream_id, data=response_body, end_stream=False)
            self._http.send_headers(
                stream_id=stream_id,
                headers=[(b"x-wknet-trailer", b"complete")],
                end_stream=True,
            )
        else:
            self._http.send_data(stream_id=stream_id, data=response_body, end_stream=True)

        if self._scenario == "goaway":
            control_stream_id = self._http._local_control_stream_id
            if control_stream_id is None:
                raise RuntimeError("HTTP/3 control stream is not initialized")
            self._quic.send_stream_data(
                control_stream_id,
                encode_frame(FrameType.GOAWAY, encode_uint_var(4)),
            )
            self._log("goaway id=4")

        if self._scenario == "key-update":
            self._quic.request_key_update()

        if self._scenario == "loss-reorder":
            datagrams = self._quic.datagrams_to_send(now=self._loop.time())
            if len(datagrams) < 2:
                raise RuntimeError("loss-reorder scenario did not produce multiple datagrams")
            dropped_data, _ = datagrams[0]
            self._log(f"impairment dropped_bytes={len(dropped_data)} reordered={len(datagrams) - 1}")
            for data, address in reversed(datagrams[1:]):
                self._transport.sendto(data, address)
            QuicConnectionProtocol.transmit(self)
            return
        self.transmit()


async def run_peer(arguments: argparse.Namespace) -> None:
    log_path = Path(arguments.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")

    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=False)
    configuration.cipher_suites = [CipherSuite.AES_128_GCM_SHA256]
    if arguments.scenario == "vn":
        configuration.supported_versions = [QuicProtocolVersion.VERSION_2]
    configuration.quic_logger = PeerQuicLogger(log_path)
    configuration.load_cert_chain(arguments.certificate, arguments.key)

    server = await serve(
        host=arguments.host,
        port=arguments.port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: Http3PeerProtocol(
            *args,
            scenario=arguments.scenario,
            log_path=log_path,
            **kwargs,
        ),
        retry=arguments.scenario == "retry",
    )

    ready_path = Path(arguments.ready_file)
    ready_path.parent.mkdir(parents=True, exist_ok=True)
    ready_path.write_text(f"ready port={arguments.port}\n", encoding="ascii")
    try:
        await asyncio.Future()
    finally:
        server.close()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="wknet aioquic HTTP/3 interoperability peer")
    parser.add_argument("-Scenario", "--scenario", required=True)
    parser.add_argument("-Port", "--port", required=True, type=int)
    parser.add_argument("-Certificate", "--certificate", required=True)
    parser.add_argument("-Key", "--key", required=True)
    parser.add_argument("-ReadyFile", "--ready-file", required=True)
    parser.add_argument("-LogFile", "--log-file", required=True)
    parser.add_argument("-Host", "--host", default="127.0.0.1")
    return parser.parse_args()


def main() -> None:
    asyncio.run(run_peer(parse_arguments()))


if __name__ == "__main__":
    main()
