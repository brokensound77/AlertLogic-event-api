""" This is the base class which Incident and Event are extended from. Credentials can be set at instantiation of
    the subclass Incident or with the appropriate methods. Customer errors are also defined for use throughout the
    program. Finally, the requests Session is declared here, outside of the class in order to preserve throughout use.
"""

import requests
import re
from html.parser import HTMLParser
from .errors import *


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
        parse_html = HTMLParser()
        login_params = {
            'audience': 'https://alertlogic.com/',
            'protocol': 'oauth2',
            'redirect_uri': 'https://console.clouddefender.alertlogic.com/core/start/auth0',
            'response_mode': 'query',
            'response_type': 'code',
            'scope': 'openid id_token',
            'connection': 'aims-global',
            'tenant': 'alertlogic',
            'username': AlertLogic.username,
            'password': AlertLogic.password
        }
        r0 = AlertLogic.alogic.get('https://console.clouddefender.alertlogic.com/')
        client_state = re.search('state=(?P<state>.+?)&', r0.url).group('state')
        client_info_raw = str(r0.history[0].headers.get('Location'))
        client_id = re.search('client_id=(?P<id>.+?)&', client_info_raw).group('id')
        client_nonce = re.search('nonce=(?P<id>.+?)&', client_info_raw).group('id')
        login_params['state'] = client_state
        login_params['client_id'] = client_id
        login_params['nonce'] = client_nonce
        r1 = AlertLogic.alogic.post('https://alertlogic.auth0.com/usernamepassword/login', data=login_params)
        callback_data_raw = r1.text
        callback_wa = re.search('name="wa".+?value="(?P<wa>.+?)"', callback_data_raw, re.DOTALL).group('wa')
        callback_wresult = re.search('name="wresult".+?value="(?P<wresult>.+?)"', callback_data_raw, re.DOTALL).group(
            'wresult')
        callback_wctx = re.search('name="wctx".+?value="(?P<wctx>.+?)"', callback_data_raw, re.DOTALL).group('wctx')
        callback_data = {
            'wa': callback_wa,
            'wresult': callback_wresult,
            'wctx': parse_html.unescape(callback_wctx)
        }
        r = AlertLogic.alogic.post('https://alertlogic.auth0.com/login/callback', data=callback_data)
        if r.status_code != 200:
            raise NotAuthenticatedError('Failed to authenticate with username and password. Status code: {0}\n'
                                        'Exception: {1}'.format(r.status_code, r.reason))
        AlertLogic.al_logged_in = True
        return

