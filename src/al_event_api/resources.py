

class AlertLogic(object):
    # shared attributes with Events and Incidents

    def __init__(self):
        pass



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