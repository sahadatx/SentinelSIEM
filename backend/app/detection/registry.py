from __future__ import annotations

from collections.abc import Iterable

from app.detection.schema import DetectionRule


class DetectionRuleRegistry:
    """
    In-memory runtime registry for validated detection rules.

    The registry is the runtime source consumed by DetectionEngine.

    Responsibilities
    ----------------
    - Register validated detection rules.
    - Replace existing rules.
    - Retrieve rules by ID.
    - List all rules.
    - List enabled rules.
    - List disabled rules.
    - Remove rules.
    - Clear runtime state.
    - Provide basic runtime rule counts.

    Non-responsibilities
    --------------------
    - Does not persist rules.
    - Does not load rules from disk/database/OpenSearch.
    - Does not perform rule CRUD authorization.
    - Does not evaluate rules.
    - Does not create alerts.
    - Does not perform RBAC.

    Persistence and synchronization belong to the Detection service /
    dedicated rule repository layer.
    """

    def __init__(
        self,
        rules: Iterable[DetectionRule] | None = None,
    ) -> None:
        self._rules: dict[str, DetectionRule] = {}

        if rules is not None:
            self.replace_many(rules)

    # ========================================================================
    # Registration
    # ========================================================================

    def register(
        self,
        rule: DetectionRule,
    ) -> None:
        """
        Register a new detection rule.

        Raises
        ------
        TypeError
            If the supplied object is not a DetectionRule.

        ValueError
            If a rule with the same ID already exists.
        """
        self._validate_rule(rule)

        rule_id = self._normalize_rule_id(rule.id)

        if rule_id in self._rules:
            raise ValueError(
                f"duplicate detection rule: {rule_id}",
            )

        self._rules[rule_id] = rule

    def replace(
        self,
        rule: DetectionRule,
    ) -> None:
        """
        Register a rule under its ID, replacing an existing rule.

        This method is also suitable for controlled runtime initialization.
        """
        self._validate_rule(rule)

        rule_id = self._normalize_rule_id(rule.id)

        self._rules[rule_id] = rule

    def register_many(
        self,
        rules: Iterable[DetectionRule],
    ) -> None:
        """
        Register multiple new detection rules.

        Registration is atomic with respect to validation and duplicate
        checking: all rules are validated and checked before the registry
        is modified.
        """
        normalized_rules = self._prepare_rules(rules)

        duplicates = [
            rule_id
            for rule_id in normalized_rules
            if rule_id in self._rules
        ]

        if duplicates:
            raise ValueError(
                "duplicate detection rule(s): "
                + ", ".join(sorted(duplicates)),
            )

        self._rules.update(normalized_rules)

    def replace_many(
        self,
        rules: Iterable[DetectionRule],
    ) -> None:
        """
        Replace/register multiple detection rules.

        Duplicate IDs within the supplied iterable are rejected rather than
        silently allowing the last item to win.
        """
        normalized_rules = self._prepare_rules(rules)

        self._rules.update(normalized_rules)

    # ========================================================================
    # Retrieval
    # ========================================================================

    def get(
        self,
        rule_id: str,
    ) -> DetectionRule | None:
        """
        Return a rule by ID.

        Returns None when the rule does not exist.
        """
        normalized_rule_id = self._normalize_rule_id(
            rule_id,
            allow_empty=True,
        )

        if not normalized_rule_id:
            return None

        return self._rules.get(normalized_rule_id)

    def all(self) -> tuple[DetectionRule, ...]:
        """
        Return all registered detection rules.

        Rules are returned in deterministic rule-ID order.
        """
        return tuple(
            self._rules[rule_id]
            for rule_id in sorted(self._rules)
        )

    def enabled(self) -> tuple[DetectionRule, ...]:
        """
        Return all enabled detection rules.

        Rules are returned in deterministic rule-ID order.
        """
        return tuple(
            rule
            for rule in self.all()
            if rule.enabled
        )

    def disabled(self) -> tuple[DetectionRule, ...]:
        """
        Return all disabled detection rules.

        Rules are returned in deterministic rule-ID order.
        """
        return tuple(
            rule
            for rule in self.all()
            if not rule.enabled
        )

    # ========================================================================
    # Removal
    # ========================================================================

    def remove(
        self,
        rule_id: str,
    ) -> DetectionRule:
        """
        Remove and return a detection rule.

        Raises
        ------
        KeyError
            If the rule does not exist.
        """
        normalized_rule_id = self._normalize_rule_id(rule_id)

        try:
            return self._rules.pop(normalized_rule_id)
        except KeyError as exc:
            raise KeyError(
                f"unknown detection rule: {normalized_rule_id}",
            ) from exc

    # ========================================================================
    # Statistics
    # ========================================================================

    def count(self) -> int:
        """
        Return the total number of registered rules.
        """
        return len(self._rules)

    def enabled_count(self) -> int:
        """
        Return the number of enabled rules.
        """
        return sum(
            1
            for rule in self._rules.values()
            if rule.enabled
        )

    def disabled_count(self) -> int:
        """
        Return the number of disabled rules.
        """
        return sum(
            1
            for rule in self._rules.values()
            if not rule.enabled
        )

    def contains(
        self,
        rule_id: str,
    ) -> bool:
        """
        Check whether a rule ID is registered.
        """
        normalized_rule_id = self._normalize_rule_id(
            rule_id,
            allow_empty=True,
        )

        if not normalized_rule_id:
            return False

        return normalized_rule_id in self._rules

    # ========================================================================
    # Lifecycle
    # ========================================================================

    def clear(self) -> None:
        """
        Remove all registered detection rules.
        """
        self._rules.clear()

    # ========================================================================
    # Internal helpers
    # ========================================================================

    @staticmethod
    def _validate_rule(
        rule: DetectionRule,
    ) -> None:
        """
        Validate the runtime registry input type.
        """
        if not isinstance(rule, DetectionRule):
            raise TypeError(
                "detection rule registry expects DetectionRule",
            )

    @classmethod
    def _prepare_rules(
        cls,
        rules: Iterable[DetectionRule],
    ) -> dict[str, DetectionRule]:
        """
        Validate and normalize a collection of rules.

        Duplicate IDs inside the supplied collection are rejected.
        """
        prepared: dict[str, DetectionRule] = {}

        for rule in rules:
            cls._validate_rule(rule)

            rule_id = cls._normalize_rule_id(rule.id)

            if rule_id in prepared:
                raise ValueError(
                    f"duplicate detection rule: {rule_id}",
                )

            prepared[rule_id] = rule

        return prepared

    @staticmethod
    def _normalize_rule_id(
        rule_id: str,
        *,
        allow_empty: bool = False,
    ) -> str:
        """
        Normalize a rule ID for registry lookup.

        DetectionRule schema already enforces the canonical ID format.
        This helper only handles surrounding whitespace and invalid
        runtime input.
        """
        if not isinstance(rule_id, str):
            raise TypeError(
                "rule_id must be a string",
            )

        normalized = rule_id.strip()

        if not normalized and not allow_empty:
            raise ValueError(
                "rule_id must not be empty",
            )

        return normalized


__all__ = [
    "DetectionRuleRegistry",
]