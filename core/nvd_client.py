import json
import math
import re
import threading
from copy import deepcopy
from dataclasses import dataclass

import requests

from core.rate_limiter import RateLimiter


class NVDError(RuntimeError):
    """NVD lookup failed or returned invalid data."""


class NVDRateLimitError(NVDError):
    """NVD rejected the request due to rate limiting."""


@dataclass(frozen=True)
class NVDSearchResult:
    query: str
    cve_ids: tuple[str, ...]
    total_results: int
    complete: bool

@dataclass(frozen=True)
class NVDCVERecord:
    cve_id: str
    vuln_status: str | None
    published: str | None
    last_modified: str | None
    configurations: tuple

class NVDClient:
    """
    Read-only NVD CVE API 2.0 client.

    Results are search candidates, not verified vulnerabilities.
    """

    API_URL = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )

    CVE_PATTERN = re.compile(
        r"^CVE-\d{4}-\d{4,}$"
    )

    MAX_RESPONSE_BYTES = 1_048_576
    MAX_RESULTS = 20

    def __init__(
        self,
        api_key=None,
        session=None,
        requests_per_second=0.1,
        timeout=10.0,
        rate_limiter=None
    ):
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Invalid NVD timeout.")

        if api_key is not None:
            if (
                not isinstance(api_key, str)
                or not api_key.strip()
                or "\r" in api_key
                or "\n" in api_key
            ):
                raise ValueError("Invalid NVD API key.")

        self.timeout = float(timeout)
        self.api_key = api_key
        self.session = session or requests.Session()

        self.rate_limiter = (
            rate_limiter
            if rate_limiter is not None
            else RateLimiter(
                requests_per_second=requests_per_second,
                max_concurrent_requests=1
            )
        )

        self.cache = {}
        self.record_cache = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_query(product, version):
        for value in (product, version):
            if not isinstance(value, str):
                raise ValueError(
                    "Product and version must be strings."
                )

            if (
                not value.strip()
                or len(value) > 100
                or any(ord(char) < 32 for char in value)
            ):
                raise ValueError(
                    "Invalid product or version."
                )

        return f"{product.strip()} {version.strip()}"

    def _download(self, query=None, cve_id=None):
        if (query is None) == (cve_id is None):
            raise ValueError(
                "Specify exactly one NVD query type."
            )

        params = (
            {"keywordSearch": query,
             "resultsPerPage": self.MAX_RESULTS}
            if query is not None
            else {"cveId": cve_id}
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "Vultron/0.1"
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            with self.session.get(
                self.API_URL,
                params=params,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                allow_redirects=False
            ) as response:

                if response.status_code in (403, 429):
                    raise NVDRateLimitError(
                        "NVD request rejected (HTTP "
                        f"{response.status_code}). "
                        "Retry later or review API credentials."
                    )

                if response.status_code != 200:
                    raise NVDError(
                        f"NVD returned HTTP {response.status_code}."
                    )

                content = bytearray()

                for chunk in response.iter_content(
                    chunk_size=8192
                ):
                    if not chunk:
                        continue

                    if (
                        len(content) + len(chunk)
                        > self.MAX_RESPONSE_BYTES
                    ):
                        raise NVDError(
                            "NVD response size limit exceeded."
                        )

                    content.extend(chunk)

                return json.loads(content.decode("utf-8"))

        except requests.exceptions.Timeout as error:
            raise NVDError(
                "NVD API request timed out."
            ) from error

        except requests.exceptions.RequestException as error:
            raise NVDError(
                "NVD API network request failed."
            ) from error

        except (UnicodeError, ValueError) as error:
            raise NVDError(
                "NVD returned invalid JSON."
            ) from error

    @classmethod
    def _parse_response(cls, query, data):
        if not isinstance(data, dict):
            raise NVDError("Invalid NVD response structure.")

        total = data.get("totalResults")
        entries = data.get("vulnerabilities")

        if (
            type(total) is not int
            or total < 0
            or not isinstance(entries, list)
            or len(entries) > cls.MAX_RESULTS
        ):
            raise NVDError("Invalid NVD search metadata.")

        cve_ids = []

        for entry in entries:
            if not isinstance(entry, dict):
                raise NVDError("Invalid CVE entry.")

            cve = entry.get("cve")

            if not isinstance(cve, dict):
                raise NVDError("Missing CVE data.")

            cve_id = cve.get("id")

            if (
                not isinstance(cve_id, str)
                or not cve_id.startswith("CVE-")
            ):
                raise NVDError("Invalid CVE identifier.")

            cve_ids.append(cve_id)

        if len(cve_ids) > total:
            raise NVDError(
                "NVD result count is inconsistent."
            )

        return NVDSearchResult(
            query=query,
            cve_ids=tuple(cve_ids),
            total_results=total,
            complete=len(cve_ids) == total
        )

    def search(self, product, version):
        """
        Search NVD for product/version keywords.

        Successful results are cached in memory.
        Failed requests are never cached.
        """

        query = self._validate_query(product, version)

        with self._lock:
            if query in self.cache:
                return self.cache[query]

            with self.rate_limiter.limit():
                data = self._download(query)

            result = self._parse_response(query, data)

            self.cache[query] = result

            return result
    @classmethod
    def _parse_cve_record(cls, requested_id, data):
        if not isinstance(data, dict):
            raise NVDError("Invalid NVD response.")

        if data.get("totalResults") != 1:
            raise NVDError(
                "CVE was not found or response is ambiguous."
            )

        vulnerabilities = data.get("vulnerabilities")

        if (
            not isinstance(vulnerabilities, list)
            or len(vulnerabilities) != 1
        ):
            raise NVDError(
                "Expected exactly one CVE record."
            )

        entry = vulnerabilities[0]

        if not isinstance(entry, dict):
            raise NVDError("Invalid vulnerability entry.")

        cve = entry.get("cve")

        if not isinstance(cve, dict):
            raise NVDError("Missing CVE object.")

        cve_id = cve.get("id")

        if (
            not isinstance(cve_id, str)
            or cve_id != requested_id
        ):
            raise NVDError("CVE identifier mismatch.")

        configurations = cve.get("configurations", [])

        if not isinstance(configurations, list):
            raise NVDError(
                "Invalid CVE configurations."
            )

        if any(
            not isinstance(config, dict)
            for config in configurations
        ):
            raise NVDError(
                "Invalid configuration entry."
            )

        for field in (
            "vulnStatus",
            "published",
            "lastModified"
        ):
            value = cve.get(field)

            if value is not None and not isinstance(
                value, str
            ):
                raise NVDError(
                    f"Invalid CVE field: {field}"
                )

        return NVDCVERecord(
            cve_id=cve_id,
            vuln_status=cve.get("vulnStatus"),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            configurations=tuple(
                deepcopy(configurations)
            )
        )

    def get_cve(self, cve_id):
        """
        Retrieve a complete NVD CVE record.

        Cached records are never returned directly.
        Callers receive independent deep copies.
        """

        if (
                not isinstance(cve_id, str)
                or not self.CVE_PATTERN.fullmatch(cve_id)
        ):
            raise ValueError("Invalid CVE identifier.")

        with self._lock:
            if cve_id in self.record_cache:
                return deepcopy(
                    self.record_cache[cve_id]
                )

            with self.rate_limiter.limit():
                data = self._download(cve_id=cve_id)

            record = self._parse_cve_record(
                cve_id,
                data
            )

            self.record_cache[cve_id] = deepcopy(
                record
            )

            return deepcopy(record)