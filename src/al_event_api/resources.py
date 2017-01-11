

class AlertLogic(object):
    # shared attributes with Events and Incidents

    def __init__(self, username, password, api_key):
        self.__api_key = username
        self.__username = password
        self.__password = api_key



    def to_json(self):
        return

