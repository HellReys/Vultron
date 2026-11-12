
from core.nvd_scan_analysis import NVDScanBatch


def validate_nvd_batch(batch):
    """
    Validate internal consistency before exporting
    an NVD batch assessment.

    This does not confirm any vulnerability.
    """

    if not isinstance(batch, NVDScanBatch):
        raise ValueError("Invalid NVD batch.")

    allowed_statuses = {
        "NO_ELIGIBLE_SERVICES",
        "COMPLETE",
        "PARTIAL",
        "ERROR",
    }

    if batch.status not in allowed_statuses:
        raise ValueError("Invalid NVD batch status.")

    if not isinstance(batch.entries, tuple):
        raise ValueError("NVD entries must be a tuple.")

    for value in (
        batch.attempted_queries,
        batch.omitted_services,
    ):
        if type(value) is not int or value < 0:
            raise ValueError("Invalid NVD query counter.")

    if batch.attempted_queries > 3:
        raise ValueError("NVD query budget exceeded.")

    if batch.attempted_queries != len(batch.entries):
        raise ValueError("NVD query count mismatch.")

    if type(batch.search_complete) is not bool:
        raise ValueError("Invalid NVD completion flag.")

    successful = 0
    failed = 0
    all_searches_complete = True

    for entry in batch.entries:
        if not isinstance(entry.product, str):
            raise ValueError("Invalid NVD product.")

        if not isinstance(entry.version, str):
            raise ValueError("Invalid NVD version.")

        if not entry.product.strip() or not entry.version.strip():
            raise ValueError("Empty NVD service identity.")

        for value in (entry.product, entry.version):
            if len(value) > 100:
                raise ValueError("NVD service identity too long.")

            if any(
                ord(char) < 32
                or ord(char) == 127
                or 0x80 <= ord(char) <= 0x9F
                for char in value
            ):
                raise ValueError(
                    "Unsafe NVD service identity."
                )

            if value != value.strip():
                raise ValueError(
                    "Unnormalized NVD service identity."
                )


        has_assessment = entry.assessment is not None
        has_error = entry.error_code is not None

        if has_assessment == has_error:
            raise ValueError(
                "NVD entry must contain either "
                "an assessment or an error."
            )

        if has_error:
            if entry.error_code not in {
                "LOOKUP_FAILED",
                "RATE_LIMIT",
            }:
                raise ValueError("Invalid NVD error code.")

            failed += 1
            continue

        successful += 1

        summary = getattr(
            entry.assessment,
            "summary",
            None,
        )

        if summary is None:
            raise ValueError("Missing CVE assessment summary.")

        if type(summary.search_complete) is not bool:
            raise ValueError("Invalid CVE completion flag.")

        if summary.search_complete is False:
            all_searches_complete = False

    complete = (
        successful > 0
        and failed == 0
        and batch.omitted_services == 0
        and all_searches_complete
    )

    expected_complete = (
        batch.status == "COMPLETE"
    )

    if batch.search_complete != expected_complete:
        raise ValueError(
            "NVD status and completion flag mismatch."
        )

    if batch.search_complete != complete:
        raise ValueError(
            "NVD completion data is inconsistent."
        )

    if batch.status == "NO_ELIGIBLE_SERVICES":
        if (
            batch.attempted_queries != 0
            or batch.omitted_services != 0
        ):
            raise ValueError(
                "Unexpected NVD entries without services."
            )

    elif batch.status == "COMPLETE":
        if not complete:
            raise ValueError(
                "Incomplete NVD batch marked COMPLETE."
            )

    elif batch.status == "PARTIAL":
        if successful == 0 or complete:
            raise ValueError(
                "Invalid PARTIAL NVD assessment."
            )

    elif batch.status == "ERROR":
        if successful != 0:
            raise ValueError(
                "Successful lookup marked ERROR."
            )

    return True
