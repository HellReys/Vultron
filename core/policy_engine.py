from pathlib import Path

import yaml

from core.header_manager import HeaderManager
from core.scope_guard import ScopeGuard


class PolicyEngine:
    """Load and validate a bug bounty program policy."""

    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.config = self._load_config()

        self._validate_config()

        program = self.config["program"]
        scope = self.config["scope"]
        scanning = self.config["scanning"]

        self.program_name = program["name"]

        self.scope_guard = ScopeGuard(
            allowed=scope["allowed"],
            excluded=scope["excluded"]
        )

        self.scanning_enabled = scanning["enabled"]

        self.authorization_confirmed = scanning[
            "authorization_confirmed"
        ]

        self.requests_per_second = scanning[
            "requests_per_second"
        ]

        self.max_concurrent_requests = scanning[
            "max_concurrent_requests"
        ]

        self.headers = HeaderManager(
            self.config.get("headers", {})
        ).build()

    def _load_config(self):
        try:
            with self.config_path.open(
                "r", encoding="utf-8"
            ) as file:
                config = yaml.safe_load(file)

        except (OSError, yaml.YAMLError) as error:
            raise ValueError(
                f"Cannot load policy configuration: {error}"
            ) from error

        if not isinstance(config, dict):
            raise ValueError(
                "Policy configuration must be a YAML mapping."
            )

        return config

    @staticmethod
    def _check_fields(data, required, section, optional=None):
        if not isinstance(data, dict):
            raise ValueError(
                f"'{section}' must be a mapping."
            )

        required = set(required)
        optional = set(optional or [])

        missing = required - set(data)
        unknown = set(data) - required - optional

        if missing:
            raise ValueError(
                f"Missing fields in '{section}': {sorted(missing)}"
            )

        if unknown:
            raise ValueError(
                f"Unknown fields in '{section}': {sorted(unknown)}"
            )

    def _validate_config(self):
        self._check_fields(
            self.config,
            {"program", "scope", "scanning"},
            "root",
            optional={"headers"}
        )

        program = self.config["program"]
        scope = self.config["scope"]
        scanning = self.config["scanning"]

        self._check_fields(
            program,
            {"name"},
            "program"
        )

        self._check_fields(
            scope,
            {"allowed", "excluded"},
            "scope"
        )

        self._check_fields(
            scanning,
            {
                "enabled",
                "authorization_confirmed",
                "requests_per_second",
                "max_concurrent_requests"
            },
            "scanning"
        )

        if (
            not isinstance(program["name"], str)
            or not program["name"].strip()
        ):
            raise ValueError(
                "Program name must be non-empty."
            )

        for field in ("allowed", "excluded"):
            entries = scope[field]

            if not isinstance(entries, list):
                raise ValueError(
                    f"Scope '{field}' must be a list."
                )

            if any(
                not isinstance(item, str) or not item.strip()
                for item in entries
            ):
                raise ValueError(
                    f"Scope '{field}' contains an invalid entry."
                )

        if not scope["allowed"]:
            raise ValueError(
                "Allowed scope cannot be empty."
            )

        for field in ("enabled", "authorization_confirmed"):
            if type(scanning[field]) is not bool:
                raise ValueError(
                    f"Scanning '{field}' must be a boolean."
                )

        rate = scanning["requests_per_second"]
        concurrency = scanning["max_concurrent_requests"]

        if (
            type(rate) not in (int, float)
            or not 0 < rate < float("inf")
        ):
            raise ValueError(
                "requests_per_second must be a positive number."
            )

        if type(concurrency) is not int or concurrency < 1:
            raise ValueError(
                "max_concurrent_requests must be a positive integer."
            )

        if (
            scanning["enabled"]
            and not scanning["authorization_confirmed"]
        ):
            raise ValueError(
                "Active scanning cannot be enabled without "
                "confirmed authorization."
            )

        HeaderManager(
            self.config.get("headers", {})
        ).build()

    def check_host(self, host):
        return self.scope_guard.check_host(host)

    def check_url(self, url):
        return self.scope_guard.check_url(url)

    def can_scan(self):
        return (
            self.scanning_enabled
            and self.authorization_confirmed
        )