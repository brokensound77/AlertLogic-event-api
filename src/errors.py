"""Custom errors"""


class AlApiError(Exception):
    """Base class for exceptions in this module"""


class NotAuthenticatedError(AlApiError):
    """Raise when a non 200 is returned"""


class CredentialsNotSet(AlApiError):
    """Placeholder for missing credentials"""


class EventNotRetrievedError(AlApiError):
    """Failed to retrieve event; most often because of authentication"""
