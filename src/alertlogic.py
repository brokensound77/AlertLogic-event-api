""" This is the base class which Incident and Event are extended from. Credentials can be set at instantiation of
    the subclass Incident or with the appropriate methods. Customer errors are also defined for use throughout the
    program. Finally, the requests Session is declared here, outside of the class in order to preserve throughout use.
"""
#TODO: update

import requests

# persistent session across all sub-classes; not instantiated within the class because this was breaking the session at
# re-instantiation within each individual Event object
alogic = requests.Session()


class AlertLogic(object):
    """Shared attributes with Events and Incidents"""

    def __init__(self, api_key=None, username=None, password=None):
        self.api_key = api_key
        self.username = username
        self.password = password

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def create_requests_session(self):
        self.alogic = requests.Session()

    def to_json(self):
        return


class Error(Exception):
    """Base class for exceptions in this module"""


class NotAuthenticatedError(Error):
    """Raise when a non 200 is returned"""


class CredentialsNotSet(Error):
    """Placeholder for missing credentials"""
