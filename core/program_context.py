from core.http_transport import HTTPTransport
from core.request_manager import RequestManager


class ProgramContext:
    """
    Shared runtime context for one bug bounty program.

    All HTTP transports created through this context
    share one RequestManager, RateLimiter and RequestBudget.
    """

    def __init__(self, policy, settings=None):
        self.policy = policy
        self.settings = settings

        self.request_manager = RequestManager(policy)

    def create_http_transport(self, **kwargs):
        """Create an HTTP transport using shared program limits."""

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