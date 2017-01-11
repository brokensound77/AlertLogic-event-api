import requests

class AlertLogic(object):
    """shared attributes with Events and Incidents"""

    def __init__(self, api_key=None, username=None, password=None):
        self.__api_key = api_key
        self.__username = username
        self.__password = password
        self.alogic = requests.Session

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def to_json(self):
        return




class Error(Exception):
    """Base class for exceptions in this module"""
    pass


class NotAuthenticatedError(Error):
    """Raise when a non 200 is returned"""


class CredentialsNotSet(Error):
    """Placeholder for missing credentials"""
