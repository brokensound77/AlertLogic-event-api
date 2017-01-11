
# TODO:

import requests

class Incidents(object):
    def __init__(self):
        self.incdident_id = ''
        self.create_date = ''
        self.customer_id = ''
        self.incident_details = ''
        self.events = ''


    def get_incident_Details(self, customer_id, incident_id, api_key=None, persist=False):


        header = {'accept': 'application/json'}
        url = 'https://api.alertlogic.net/api/incident/v3/incidents?incident_id=' + incident_id + \
              '&customer_id=' + customer_id
        r = requests.get(url, headers=header, auth=(self.__api_key, ''))
        if r.status_code != 200:
            raise Exception('Failed to retrieve incident. Status code: {0}\nException: {1}'.format(
                r.status_code, r.reason))
        try:
            #cust_id = str(r.json()[0]['customer_id'])
            event_list = list(r.json()[0]['event_ids'])
        except IndexError as e:
            raise Exception('Events not returned from AL API. Check incident_id.\nException: {0}'.format(e))
        #if persist: self.event = cust_id, event_list)  # sets global
        return event_list

        # make api call and return json
        details = ''
        '''
        [
            {
        "acknowledge_status": "Acknowledged - Completed Analysis",
        "acknowledged_by": 12345,
        "acknowledged_date": 1426514330,
        "begin_date": 1426513500,
        "closed_by": null,
        "closed_date": null,
        "closed_type": 0,
        "correlation_end_date": 1426599900,
        "correlation_start_date": 1426427100,
        "create_date": 1426514330,
        "created_by": 0,
        "customer_id": 01234,
        "customer_name": "ABC Company, inc.",
        "description": "**Attack Detail**:  \n**Attacker Location:** 192.168.0.0, Ukraine  \n**Targeted Server**: 10.0.0.0\n\nWe have detected a recon attack against your web application using known malicious SQL commands.  These attacks are designed to map your database and attempt to steal user and company data. We have not detected any indication of success or progress. If we do the incident will evolve up and be escalated to an Analyst for further review.  \n\n**Remediation Recommendation:**  \nIf this is not expected traffic you should block the scanning IP address at your perimeter firewall.\nWhen designing your SQL database and front end application it's best to follow the below procedures to minimize the risk.  \n\nSQL Primary Defenses:\n \n* Review use of Prepared Statements (Parameterized Queries) \n* Review use of Stored Procedures \n* Escaping all User Supplied Input\n* Avoid disclosing error information \n \n[OWASP SQL Injection Cheat Sheet](https://www.owasp.org/index.php/SQL\\_Injection\\_Prevention\\_Cheat\\_Sheet) \n",
        "end_date": 1426513500,
        "evolution_root": 1111111,
        "evolution_tree": {
            "evolved_from": [],
            "incident_id": 1111111
        },
        "evolved_to": null,
        "incident_id": 1111111,
        "is_proxy": false,
        "last_modified_date": 1426514330,
        "modified_by": null,
        "num_evts": 6,
        "open": 1,
        "reopen_date": null,
        "summary": "SQL Injection Recon Attempts from 192.168.0.0\n",
        "threat_rating": "Medium",
        "class_name": "application-attack",
        "attackers": [
            "192.168.0.0"
        ],
        "victims": [
            "10.0.0.0"
        ],
        "geoip": {
            "194.168.0.0": {
                "country_code": "UA",
                "country_code3": "UKR",
                "country_name": "Ukraine",
                "region": null,
                "city": null,
                "postal_code": null,
                "latitude": 49,
                "longitude": 32,
                "area_code": 0,
                "dma_code": 0
            }
        },
        "vector": {
            "type": "web_attack_recon",
            "sub_type": "sqli"
        },
        "devices": [
            {
                "device_id": "222222",
                "sensor_id": 5555,
                "name": "device-ids-01"
            }
        ],
        "event_ids": [
            1234464,
            1234466,
            1234475,
            1234477,
            1234486,
            1234486,
            1234488
                ]
            }
        ]
        '''




        self.incident_details




class EventsPacketSummary(object):
    #  belongs to Events
    def __init__(self):
        self.details = ''  # TODO: rename to breakout
        self.summary = ''  # object --> PacketSummarySummary


class PacketSummarySummary(object):
    # belongs to EventsPacketSummary
    def __init__(self):
        self.unique_signatures = ''  # dict --> sig: event_id
        self.unique_hosts = ''  # dict --> host: event_id
        self.response_code_tally = ''  # dict --> code: event_id



class Error(Exception):
    """Base class for exceptions in this module"""
    pass

class TempExampleError(Error):
    """Placeholder for custom exceptions"""
    pass
