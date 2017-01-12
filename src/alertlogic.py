""" Update """
#TODO: update

import requests

# persistent session across all sub-classes; not instantiated within the class because this was breaking the session at
# re-instantiation within each individual Event object
alogic = requests.Session()


class AlertLogic(object):
    """shared attributes with Events and Incidents"""

    def __init__(self, api_key=None, username=None, password=None):
        self.api_key = api_key
        self.username = username
        self.password = password

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def create_requests_session(self):  # TODO: This likely needs to go away; Session is created outside of the class
        self.alogic = requests.Session()

    def to_json(self):
        return


class AlApiError(Exception):
    """Base class for exceptions in this module"""


class NotAuthenticatedError(AlApiError):
    """Raise when a non 200 is returned"""


class CredentialsNotSet(AlApiError):
    """Placeholder for missing credentials"""


class EventNotRetrievedError(AlApiError):
    """Failed to retrieve event; most often because of authentication"""
