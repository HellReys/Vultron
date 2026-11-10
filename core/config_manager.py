import math
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class AppSettings:
    name: str


@dataclass(frozen=True)
class HTTPSettings:
    timeout: float
    max_response_bytes: int


@dataclass(frozen=True)
class Settings:
    app: AppSettings
    http: HTTPSettings


class ConfigurationManager:
    """Load and validate Vultron's global settings."""

    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = Path(config_path)

    @staticmethod
    def _check_fields(data, required, section):
        if not isinstance(data, dict):
            raise ValueError(
                f"'{section}' must be a YAML mapping."
            )

        missing = set(required) - set(data)
        unknown = set(data) - set(required)

        if missing:
            raise ValueError(
                f"Missing fields in '{section}': {sorted(missing)}"
            )

        if unknown:
            raise ValueError(
                f"Unknown fields in '{section}': {sorted(unknown)}"
            )

    def load(self):
        """Return validated, immutable configuration values."""

        try:
            with self.config_path.open(
                "r", encoding="utf-8"
            ) as file:
                config = yaml.safe_load(file)

        except (OSError, yaml.YAMLError) as error:
            raise ValueError(
                f"Cannot load global configuration: {error}"
            ) from error

        self._check_fields(
            config,
            {"app", "http"},
            "root"
        )

        app = config["app"]
        http = config["http"]

        self._check_fields(
            app,
            {"name"},
            "app"
        )

        self._check_fields(
            http,
            {"timeout", "max_response_bytes"},
            "http"
        )

        name = app["name"]

        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                "Application name must be a non-empty string."
            )

        timeout = http["timeout"]

        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError(
                "HTTP timeout must be between 0 and 60 seconds."
            )

        max_bytes = http["max_response_bytes"]

        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= 10485760
        ):
            raise ValueError(
                "Maximum response size must be "
                "between 1 and 10485760 bytes."
            )

        return Settings(
            app=AppSettings(name=name.strip()),
            http=HTTPSettings(
                timeout=float(timeout),
                max_response_bytes=max_bytes
            )
        )