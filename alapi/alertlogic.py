""" This is the base class which Incident and Event are extended from. Credentials can be set at instantiation of
    the subclass Incident or with the appropriate methods. Customer errors are also defined for use throughout the
    program. Finally, the requests Session is declared here, outside of the class in order to preserve throughout use.
"""

import requests
from errors import *


class ALCommon(object):
    """class for shared attributes across all classes"""

    def to_json(self):
        """ to return json implementation"""
        return


class AlertLogic(ALCommon):
    """Shared attributes with Events and Incidents; primarily credentials"""
    api_key = None
    username = None
    password = None
    al_logged_in = False         # allows sub classes to detect if a log-in was already initiated
    alogic = requests.Session()  # persistent session across all sub-classes

    def set_api_key(self, api_key):
        AlertLogic.api_key = api_key

    def set_credentials(self, username, password):
        """Sets global credentials and logs into Alert Logic with the session"""
        AlertLogic.username = username
        AlertLogic.password = password
        AlertLogic.login_al(self)

    def reset_requests_session(self):
        """ resets request session for all """
        AlertLogic.alogic = requests.Session()

    def login_al(self):
        login_params = {#'SMENC': 'ISO-8859-1',
                        'SMLOCALE': 'US-EN',
                        'target': '-SM-/',
                        'SMAUTHREASON': 0,
                        'user': AlertLogic.username,
                        'password': AlertLogic.password
                        }
        r = AlertLogic.alogic.post('https://console.clouddefender.alertlogic.com/forms/login2.fcc', data=login_params)
        if r.status_code != 200:
            raise NotAuthenticatedError('Failed to authenticate with username and password. Status code: {0}\n'
                                        'Exception: {1}'.format(r.status_code, r.reason))
        AlertLogic.al_logged_in = True
        return


