from core.http_transport import HTTPTransport
from core.request_manager import RequestManager


class ProgramContext:
    """
    Shared runtime context for one bug bounty program.

    All HTTP transports created through this context
    share one RequestManager and its RateLimiter.
    """

    def __init__(self, policy):
        self.policy = policy
        self.request_manager = RequestManager(policy)

    def create_http_transport(self, **kwargs):
        """Create an HTTP transport using the shared request budget."""

        if "request_manager" in kwargs:
            raise ValueError(
                "RequestManager is owned by ProgramContext."
            )

        if "policy" in kwargs:
            raise ValueError(
                "Policy is owned by ProgramContext."
            )

        return HTTPTransport(
            policy=self.policy,
            request_manager=self.request_manager,
            **kwargs
        )
