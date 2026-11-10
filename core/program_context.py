from core.http_transport import HTTPTransport
from core.request_manager import RequestManager
from core.rate_limiter import RateLimiter
from core.request_budget import RequestBudget
from core.tcp_scanner import PolicyAwareTCPScanner


class ProgramContext:
    """
    Shared runtime context for one bug bounty program.

    HTTP and TCP use separate limits.

    All transports and scanners created through this context
    share their corresponding rate limiters and budgets.
    """

    def __init__(self, policy, settings=None):
        self.policy = policy
        self.settings = settings

        # Shared HTTP controls.
        self.request_manager = RequestManager(policy)

        # Shared TCP controls.
        self.tcp_rate_limiter = None
        self.tcp_budget = None

        tcp_policy = getattr(policy, "tcp_policy", None)

        if tcp_policy is not None:
            self.tcp_rate_limiter = RateLimiter(
                requests_per_second=(
                    tcp_policy.connections_per_second
                ),
                max_concurrent_requests=1
            )

            self.tcp_budget = RequestBudget(
                tcp_policy.max_connections
            )

    def create_http_transport(self, **kwargs):
        """Create an HTTP transport with shared HTTP limits."""

        if "request_manager" in kwargs:
            raise ValueError(
                "RequestManager is owned by ProgramContext."
            )

        if "policy" in kwargs:
            raise ValueError(
                "Policy is owned by ProgramContext."
            )

        if self.settings is not None:
            kwargs.setdefault(
                "timeout",
                self.settings.http.timeout
            )

            kwargs.setdefault(
                "max_response_bytes",
                self.settings.http.max_response_bytes
            )

        return HTTPTransport(
            policy=self.policy,
            request_manager=self.request_manager,
            **kwargs
        )

    def create_tcp_scanner(self, **kwargs):
        """Create a TCP scanner using shared TCP limits."""

        protected = {
            "policy",
            "rate_limiter",
            "budget"
        }

        overridden = protected.intersection(kwargs)

        if overridden:
            raise ValueError(
                "TCP scanner shared controls are owned "
                "by ProgramContext: "
                f"{sorted(overridden)}"
            )

        if (
            self.tcp_rate_limiter is None
            or self.tcp_budget is None
        ):
            raise ValueError(
                "TCP policy is not configured."
            )

        return PolicyAwareTCPScanner(
            policy=self.policy,
            rate_limiter=self.tcp_rate_limiter,
            budget=self.tcp_budget,
            **kwargs
        )