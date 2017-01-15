""" This is the base class which Incident and Event are extended from. Credentials can be set at instantiation of
    the subclass Incident or with the appropriate methods. Customer errors are also defined for use throughout the
    program. Finally, the requests Session is declared here, outside of the class in order to preserve throughout use.
"""
#TODO: update

import requests
from errors import *

# persistent session across all sub-classes; not instantiated within the class because this was breaking the session at
# re-instantiation within each individual Event object
alogic = requests.Session()


class AlertLogic(object):
    """Shared attributes with Events and Incidents"""
    api_key = None
    username = None
    password = None

    def __init__(self):#, api_key=None, username=None, password=None):
        #self.api_key = api_key
        #self.username = username
        #self.password = password
        #AlertLogic.api_key = api_key
        #AlertLogic.username = username
        #AlertLogic.password = password
        pass

    def set_api_key(self, api_key):
        AlertLogic.api_key = api_key

    def set_credentials(self, username, password):
        AlertLogic.username = username
        AlertLogic.password = password

    def reset_requests_session(self):  # TODO: This likely needs to go away; Session is created outside of the class
        alogic = requests.Session()

    def to_json(self):
        return


