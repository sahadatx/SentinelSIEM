from __future__ import annotations

from dataclasses import dataclass

from app.domain.events.enums import EventSourceType
from app.domain.events.models import RawEvent


# ============================================================
# Source Route Resolver
# ============================================================


@dataclass(frozen=True, slots=True)
class SourceRouteResolver:
    """
    Resolve a RawEvent to the logical parsing route that should
    process it.

    Routing is intentionally kept outside the parser registry and
    parsing pipeline so that parser selection remains centralized.

    Supported routes:

        linux_auth
        generic_security
    """

    tcp_route: str = "linux_auth"
    syslog_route: str = "linux_auth"
    generic_security_route: str = "generic_security"

    # --------------------------------------------------------
    # Generic security-event marker
    # --------------------------------------------------------

    generic_security_prefix: str = "SECURITY_EVENT"

    # ========================================================
    # Public API
    # ========================================================

    def resolve(self, event: RawEvent) -> str:
        """
        Resolve the parsing route for a RawEvent.

        Routing rules:

        1. TCP SECURITY_EVENT messages
           -> generic_security

        2. Other TCP messages
           -> configured tcp_route

        3. SYSLOG messages
           -> configured syslog_route

        4. Unsupported source types
           -> ValueError
        """

        if not isinstance(event, RawEvent):
            raise TypeError(
                "source route resolver expects RawEvent",
            )

        if event.source_type == EventSourceType.TCP:
            if self._is_generic_security_event(event):
                return self.generic_security_route

            return self.tcp_route

        if event.source_type == EventSourceType.SYSLOG:
            if self._is_generic_security_event(event):
                return self.generic_security_route

            return self.syslog_route

        raise ValueError(
            "no parsing route configured for source type "
            f"{event.source_type!r}",
        )

    # ========================================================
    # Generic Security Detection
    # ========================================================

    def _is_generic_security_event(
        self,
        event: RawEvent,
    ) -> bool:
        """
        Determine whether a RawEvent contains the generic
        SECURITY_EVENT format.

        Only the beginning of the message is inspected so that
        arbitrary field values do not affect route selection.
        """

        raw_event = event.raw_event

        if not isinstance(raw_event, str):
            return False

        message = raw_event.strip()

        if not message:
            return False

        # ----------------------------------------------------
        # Direct format:
        #
        # SECURITY_EVENT action=...
        # ----------------------------------------------------

        if message.startswith(
            self.generic_security_prefix,
        ):
            return True

        # ----------------------------------------------------
        # Syslog-wrapped format:
        #
        # Sep 07 10:20:30 host app:
        # SECURITY_EVENT action=...
        #
        # The generic parser itself understands the syslog
        # prefix, so routing must also recognize it here.
        # ----------------------------------------------------

        message = self._strip_syslog_prefix(message)

        return message.startswith(
            self.generic_security_prefix,
        )

    # ========================================================
    # Syslog Prefix Handling
    # ========================================================

    @staticmethod
    def _strip_syslog_prefix(
        raw_event: str,
    ) -> str:
        """
        Remove a standard syslog prefix when present.

        Supported examples:

            Sep 07 10:20:30 host sshd:
            <34>Sep 07 10:20:30 host sshd[1234]:

        The method intentionally performs lightweight detection.
        Full syslog parsing remains the parser's responsibility.
        """

        value = raw_event.strip()

        if not value:
            return value

        # ----------------------------------------------------
        # Optional priority prefix
        # ----------------------------------------------------

        if value.startswith("<"):
            closing = value.find(">")

            if closing > 1:
                priority = value[1:closing]

                if priority.isdigit():
                    value = value[closing + 1 :].lstrip()

        # ----------------------------------------------------
        # Minimum syslog structure:
        #
        # Mon DD HH:MM:SS HOST PROCESS:
        # ----------------------------------------------------

        parts = value.split(None, 5)

        if len(parts) < 6:
            return raw_event.strip()

        month = parts[0]
        day = parts[1]
        clock = parts[2]
        hostname = parts[3]
        process = parts[4]
        remainder = parts[5]

        if (
            len(month) != 3
            or not month[0].isalpha()
            or not day.isdigit()
            or len(clock) != 8
            or clock[2] != ":"
            or clock[5] != ":"
        ):
            return raw_event.strip()

        if not hostname:
            return raw_event.strip()

        if not process:
            return raw_event.strip()

        # Process normally ends with ":" or process[pid]:
        if ":" not in remainder:
            return raw_event.strip()

        message_separator = remainder.find(":")

        if message_separator < 0:
            return raw_event.strip()

        return remainder[
            message_separator + 1 :
        ].strip()


# ============================================================
# Public API
# ============================================================


__all__ = [
    "SourceRouteResolver",
]