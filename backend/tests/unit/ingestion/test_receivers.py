from app.domain.events.enums import EventSourceType
from app.ingestion.receivers.file import FileReceiver
from app.ingestion.receivers.http import HTTPReceiver
from app.ingestion.receivers.syslog import SyslogReceiver
from app.ingestion.receivers.tcp import TCPReceiver


def test_syslog_receiver_creates_raw_event() -> None:
    event = SyslogReceiver().receive("login failed", source="auth01")
    assert event.source_type == EventSourceType.SYSLOG


def test_http_receiver_creates_raw_event() -> None:
    event = HTTPReceiver().receive("{}", source="api01")
    assert event.source_type == EventSourceType.HTTP


def test_tcp_receiver_creates_raw_event() -> None:
    event = TCPReceiver().receive("payload", source="tcp01")
    assert event.source_type == EventSourceType.TCP


def test_file_receiver_creates_raw_events() -> None:
    events = FileReceiver().receive_lines(["one\n", "two\n"], source="auth.log")
    assert [event.raw_event for event in events] == ["one", "two"]
