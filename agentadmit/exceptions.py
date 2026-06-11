"""
agentadmit.exceptions
---------------------
Custom exceptions for the AgentAdmit SDK.
"""


class AgentAdmitError(Exception):
    """Base exception for all AgentAdmit errors."""
    pass


class InvalidTokenError(AgentAdmitError):
    """Token validation failed — expired, malformed, bad signature, or wrong audience."""
    def __init__(self, message: str = "Invalid access token", error_code: str = "invalid_token"):
        self.error_code = error_code
        super().__init__(message)


class InsufficientScopeError(AgentAdmitError):
    """Agent does not have the required scope for this action."""
    def __init__(self, required_scope: str, granted_scopes: list):
        self.required_scope = required_scope
        self.granted_scopes = granted_scopes
        super().__init__(
            f"This action requires '{required_scope}' scope. "
            f"Granted scopes: {granted_scopes}"
        )


class ConnectionRevokedError(AgentAdmitError):
    """The agent connection has been revoked or does not exist."""
    def __init__(self, connection_id: str = ""):
        self.connection_id = connection_id
        super().__init__("This agent connection has been revoked or does not exist")


class ConnectionLimitError(AgentAdmitError):
    """User has reached their maximum number of active agent connections."""
    def __init__(self, tier: str, limit: int, current: int):
        self.tier = tier
        self.limit = limit
        self.current = current
        super().__init__(
            f"Your {tier} plan allows a maximum of {limit} active agent connections. "
            f"Currently using {current}. Revoke an existing connection or upgrade."
        )


class ConfigurationError(AgentAdmitError):
    """SDK is misconfigured — missing keys, bad config file, etc."""
    def __init__(self, message: str = "AgentAdmit SDK configuration error"):
        super().__init__(message)


class WebhookSignatureError(AgentAdmitError):
    """Inbound alert webhook failed X-AgentAdmit-Signature verification."""
    def __init__(self, message: str = "Webhook signature verification failed"):
        super().__init__(message)


class RateLimitError(AgentAdmitError):
    """
    The AgentAdmit introspection endpoint returned 429 Too Many Requests
    and all retry attempts were exhausted.

    Attributes:
        retry_after: seconds to wait before retrying (from Retry-After header), or None
        limit: total request limit for the window (X-RateLimit-Limit), or None
        remaining: requests remaining in the current window (X-RateLimit-Remaining), or None
        reset: Unix timestamp when the rate limit window resets (X-RateLimit-Reset), or None
    """
    def __init__(
        self,
        message: str = "AgentAdmit rate limit exceeded. Max retries exhausted.",
        retry_after: float | None = None,
        limit: int | None = None,
        remaining: int | None = None,
        reset: int | None = None,
    ):
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        super().__init__(message)
