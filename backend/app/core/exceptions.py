"""Domain exceptions with investigator-friendly messages."""


class ForensicsError(Exception):
    """Base class for expected, user-facing errors."""

    status_code = 400

    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class EvidenceValidationError(ForensicsError):
    status_code = 422


class EvidenceTooLargeError(ForensicsError):
    status_code = 413


class NotFoundError(ForensicsError):
    status_code = 404


class VolatilityUnavailableError(ForensicsError):
    status_code = 503


class AIProviderError(ForensicsError):
    status_code = 502
