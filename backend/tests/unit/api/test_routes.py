from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.dependencies import APIContainer
from app.api.schemas.events import EventFilterOptions
from app.domain.events.models import EnrichedEvent
from app.main import build_application


class FakeEventRepository:
    """In-memory event repository for API route tests."""

    def __init__(
        self,
        events: list[EnrichedEvent] | None = None,
    ) -> None:
        self.events = list(events or [])

        self.last_search_kwargs: dict[str, Any] | None = None

    async def search(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Any:
        """Search the in-memory event collection."""
        self.last_search_kwargs = {
            "query": query,
            "source": source,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "username": username,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "category": category,
            "start_time": start_time,
            "end_time": end_time,
            "offset": offset,
            "limit": limit,
        }

        filtered = list(self.events)

        if query:
            normalized_query = query.strip().lower()

            filtered = [
                event
                for event in filtered
                if (
                    normalized_query in event.raw_event.lower()
                    or (
                        event.username is not None
                        and normalized_query
                        in event.username.lower()
                    )
                    or (
                        event.action is not None
                        and normalized_query
                        in event.action.lower()
                    )
                    or (
                        event.command is not None
                        and normalized_query
                        in event.command.lower()
                    )
                    or (
                        event.process is not None
                        and normalized_query
                        in event.process.lower()
                    )
                )
            ]

        if source is not None:
            filtered = [
                event
                for event in filtered
                if event.source == source
            ]

        if source_ip is not None:
            filtered = [
                event
                for event in filtered
                if str(event.source_ip) == source_ip
            ]

        if destination_ip is not None:
            filtered = [
                event
                for event in filtered
                if (
                    event.destination_ip is not None
                    and str(event.destination_ip)
                    == destination_ip
                )
            ]

        if username is not None:
            filtered = [
                event
                for event in filtered
                if event.username == username
            ]

        if action is not None:
            filtered = [
                event
                for event in filtered
                if event.action == action
            ]

        if outcome is not None:
            filtered = [
                event
                for event in filtered
                if event.outcome.value == outcome
            ]

        if severity is not None:
            filtered = [
                event
                for event in filtered
                if event.severity.value == severity
            ]

        if category is not None:
            filtered = [
                event
                for event in filtered
                if event.category.value == category
            ]

        if start_time is not None:
            filtered = [
                event
                for event in filtered
                if event.timestamp >= start_time
            ]

        if end_time is not None:
            filtered = [
                event
                for event in filtered
                if event.timestamp <= end_time
            ]

        total = len(filtered)

        return type(
            "EventSearchResult",
            (),
            {
                "events": tuple(
                    filtered[offset : offset + limit]
                ),
                "total": total,
            },
        )()

    async def get(
        self,
        event_id: Any,
    ) -> EnrichedEvent | None:
        """Retrieve an event by ID."""
        for event in self.events:
            if event.event_id == event_id:
                return event

        return None


class FakeEventFilterOptionsRepository(FakeEventRepository):
    """Repository exposing deterministic filter-option values."""

    async def get_filter_options(self) -> EventFilterOptions:
        """Return dynamic event filter options."""
        return EventFilterOptions(
            sources=[
                "another-source",
                "test-source",
            ],
            users=[
                "user-0",
                "user-1",
                "user-2",
            ],
            actions=[
                "login",
                "logout",
            ],
            outcomes=[
                "failure",
                "success",
            ],
            severities=[
                "high",
                "low",
            ],
            categories=[
                "authentication",
                "network",
            ],
        )


async def _create_events(
    count: int,
) -> list[EnrichedEvent]:
    """Create minimal enriched events for API tests."""
    events: list[EnrichedEvent] = []

    for index in range(count):
        event = EnrichedEvent(
            event_id=uuid4(),
            timestamp=datetime(
                2026,
                9,
                1,
                12,
                0,
                index,
                tzinfo=timezone.utc,
            ),
            ingestion_timestamp=datetime(
                2026,
                9,
                1,
                12,
                0,
                index,
                tzinfo=timezone.utc,
            ),
            source="test-source",
            source_type="syslog",
            hostname="test-host",
            source_ip="10.10.10.10",
            destination_ip=None,
            source_port=54321,
            destination_port=None,
            protocol="tcp",
            username=f"user-{index}",
            process="sshd",
            command=None,
            action="login",
            outcome="failure",
            severity="high",
            category="authentication",
            raw_event=f"failed password user-{index}",
            parsed_data={},
            normalized_data={},
            enrichment={},
            metadata={},
            stage="enriched",
        )

        events.append(event)

    return events


def _build_client(
    repository: FakeEventRepository,
) -> TestClient:
    """Build an API client with an injected event repository."""
    container = APIContainer(
        event_repository=repository,
    )

    app = build_application(
        api_container=container,
    )

    return TestClient(app)


def test_v1_health_and_system() -> None:
    app = build_application(
        api_container=APIContainer(),
    )

    client = TestClient(app)

    health = client.get("/api/v1/health")
    system = client.get("/api/v1/system")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    assert system.status_code == 200
    assert "api" in system.json()["capabilities"]


def test_events_without_repository_returns_service_unavailable() -> None:
    app = build_application(
        api_container=APIContainer(),
    )

    client = TestClient(app)

    response = client.get("/api/v1/events")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "event repository is not configured"
    )


def test_events_returns_paginated_response() -> None:
    events = _run_async(_create_events(3))

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "page": 1,
            "page_size": 2,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 2

    assert data["pagination"]["page"] == 1
    assert data["pagination"]["page_size"] == 2
    assert data["pagination"]["total"] == 3

    assert repository.last_search_kwargs is not None
    assert repository.last_search_kwargs["offset"] == 0
    assert repository.last_search_kwargs["limit"] == 2


def test_events_second_page_returns_next_events() -> None:
    events = _run_async(_create_events(5))

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    first_response = client.get(
        "/api/v1/events",
        params={
            "page": 1,
            "page_size": 2,
        },
    )

    second_response = client.get(
        "/api/v1/events",
        params={
            "page": 2,
            "page_size": 2,
        },
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_items = first_response.json()["items"]
    second_items = second_response.json()["items"]

    assert len(first_items) == 2
    assert len(second_items) == 2

    first_ids = {
        item["event_id"]
        for item in first_items
    }

    second_ids = {
        item["event_id"]
        for item in second_items
    }

    assert first_ids.isdisjoint(second_ids)

    assert (
        second_response.json()["pagination"]["page"]
        == 2
    )

    assert (
        second_response.json()["pagination"]["page_size"]
        == 2
    )

    assert (
        second_response.json()["pagination"]["total"]
        == 5
    )

    assert repository.last_search_kwargs is not None
    assert repository.last_search_kwargs["offset"] == 2
    assert repository.last_search_kwargs["limit"] == 2


def test_events_applies_source_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].source = "another-source"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "source": "another-source",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["source"] == "another-source"


def test_events_applies_source_ip_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].source_ip = "192.168.1.50"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "source_ip": "192.168.1.50",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["source_ip"] == "192.168.1.50"


def test_events_applies_destination_ip_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].destination_ip = "192.168.1.100"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "destination_ip": "192.168.1.100",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["destination_ip"] == (
        "192.168.1.100"
    )


def test_events_applies_user_filter() -> None:
    events = _run_async(_create_events(3))

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "username": "user-1",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["username"] == "user-1"


def test_events_applies_action_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].action = "logout"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "action": "logout",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["action"] == "logout"


def test_events_applies_outcome_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].outcome = "success"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "outcome": "success",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["outcome"] == "success"


def test_events_applies_severity_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].severity = "low"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "severity": "low",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["severity"] == "low"


def test_events_applies_category_filter() -> None:
    events = _run_async(_create_events(3))

    events[1].category = "network"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "category": "network",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["category"] == "network"


def test_events_applies_combined_filters() -> None:
    events = _run_async(_create_events(4))

    events[1].username = "target-user"
    events[1].action = "logout"
    events[1].outcome = "success"
    events[1].severity = "low"
    events[1].category = "network"
    events[1].source = "special-source"
    events[1].source_ip = "10.20.30.40"
    events[1].destination_ip = "192.168.10.20"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "source": "special-source",
            "source_ip": "10.20.30.40",
            "destination_ip": "192.168.10.20",
            "username": "target-user",
            "action": "logout",
            "outcome": "success",
            "severity": "low",
            "category": "network",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1

    item = data["items"][0]

    assert item["username"] == "target-user"
    assert item["action"] == "logout"
    assert item["outcome"] == "success"
    assert item["severity"] == "low"
    assert item["category"] == "network"
    assert item["source"] == "special-source"
    assert item["source_ip"] == "10.20.30.40"
    assert item["destination_ip"] == "192.168.10.20"


def test_events_applies_search_to_action() -> None:
    events = _run_async(_create_events(3))

    events[1].action = "logout"
    events[1].raw_event = "user logout completed"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "query": "logout",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["action"] == "logout"


def test_events_applies_search_to_process() -> None:
    events = _run_async(_create_events(3))

    events[1].process = "sudo"

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    response = client.get(
        "/api/v1/events",
        params={
            "query": "sudo",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["process"] == "sudo"


def test_events_applies_time_range() -> None:
    events = _run_async(_create_events(3))

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    start_time = datetime(
        2026,
        9,
        1,
        12,
        0,
        1,
        tzinfo=timezone.utc,
    )

    end_time = datetime(
        2026,
        9,
        1,
        12,
        0,
        2,
        tzinfo=timezone.utc,
    )

    response = client.get(
        "/api/v1/events",
        params={
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["pagination"]["total"] == 2
    assert len(data["items"]) == 2


def test_events_rejects_invalid_time_range() -> None:
    events = _run_async(_create_events(3))

    repository = FakeEventRepository(events)
    client = _build_client(repository)

    start_time = datetime(
        2026,
        9,
        1,
        13,
        0,
        tzinfo=timezone.utc,
    )

    end_time = datetime(
        2026,
        9,
        1,
        12,
        0,
        tzinfo=timezone.utc,
    )

    response = client.get(
        "/api/v1/events",
        params={
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "start_time must not be later than end_time"
    )


def test_events_rejects_invalid_page() -> None:
    app = build_application(
        api_container=APIContainer(),
    )

    client = TestClient(app)

    response = client.get(
        "/api/v1/events",
        params={
            "page": 0,
        },
    )

    assert response.status_code == 422


def test_events_rejects_invalid_page_size() -> None:
    app = build_application(
        api_container=APIContainer(),
    )

    client = TestClient(app)

    response = client.get(
        "/api/v1/events",
        params={
            "page_size": 0,
        },
    )

    assert response.status_code == 422


def test_request_id_is_returned() -> None:
    app = build_application(
        api_container=APIContainer(),
    )

    client = TestClient(app)

    response = client.get(
        "/api/v1/system",
        headers={
            "X-Request-ID": "test-request-123",
        },
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == (
        "test-request-123"
    )


def _run_async(coro: Any) -> Any:
    """Run a coroutine for synchronous test setup."""
    import asyncio

    return asyncio.run(coro)
