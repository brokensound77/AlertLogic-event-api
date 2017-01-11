

class AlertLogic(object):
    """shared attributes with Events and Incidents"""

    def __init__(self):
        self.__api_key = ''
        self.__username = ''
        self.__password = ''
        #self.set_api_key()
        #self.set_credentials()

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


class TempExampleError(Error):
    """Placeholder for custom exceptions"""
    pass