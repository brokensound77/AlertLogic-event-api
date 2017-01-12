""" Update """
#TODO: update

import threading
from alertlogic import *
from events import Event


class Incident(AlertLogic):
    """If credentials are not instantiated, then they must be set prior to implementation with set_api_key and
        set_credentials
    """

    def __init__(self, incident_id, customer_id='all_children', api_key=None, username=None, password=None):
        AlertLogic.__init__(self, api_key, username, password)
        self.incident_id = str(incident_id)
        self.customer_id = str(customer_id)  # all_children includes all customer accounts that the caller can access
        self.incident_details = ''  # JSON; get_incident_details()
        self.event_ids = ''  # list of str; retrieved and set in get_incident_details
        if self.api_key is not None:
            self.get_incident_details()  # sets incident_details and event_ids
        if username is not None and password is not None:
            self.login_al()  # authenticates with a session to preserve for event iteration
            self.Events = self.get_event_objects()  # list; Event class objects; set by get_events() #TODO: capitalize object
            self.events_summary = self.get_event_summary()  # dict; 'breakdown': {}, 'summary': object()  #TODO: capitalize object

    def login_al(self):
        login_params = {#'SMENC': 'ISO-8859-1',
                        'SMLOCALE': 'US-EN',
                        'target': '-SM-/',
                        'SMAUTHREASON': 0,
                        'user': self.username,
                        'password': self.password
                        }
        r = alogic.post('https://console.clouddefender.alertlogic.com/forms/login2.fcc', data=login_params)
        if r.status_code != 200:
            raise NotAuthenticatedError('Failed to authenticate with username and password. Status code: {0}\n'
                                        'Exception: {1}'.format(r.status_code, r.reason))
        return

    def get_incident_details(self):
        """Makes a call to the API in order to set self.incident_details with the incident details. Schema per their
        site below (as of January 2017):
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
        """

        if self.api_key is None:
            raise CredentialsNotSet('Missing api key. If not instantiated, set with set_api_key()')
        header = {'accept': 'application/json'}
        url = 'https://api.alertlogic.net/api/incident/v3/incidents?incident_id={0}&customer_id={1}'.format(
            self.incident_id, self.customer_id)
        r = requests.get(url, headers=header, auth=(self.api_key, ''))
        if r.status_code != 200:
            raise NotAuthenticatedError('API Failed to authenticate')
        try:
            self.incident_details = r.json()
            self.event_ids = list(r.json()[0]['event_ids'])
            return
        except requests.RequestException:
            raise requests.RequestException('An error occurred trying to parse the incident details from "requests"')

    def get_event_object(self, event_id):
        if self.username is None or self.password is None:
            raise CredentialsNotSet('Missing username or password. If not instantiated, set with set_credentials()')
        return Event(event_id, self.customer_id)

    def get_event_objects(self):
        event_object_dict = {}
        #for event_id in self.event_ids:
        #    event_object_dict[event_id] = self.get_event_object(event_id)
        #return event_object_dict
        threads = []
        errors = []  # TODO: How to handle errors collected? Use suppress flag? Auto-inclusion in the dict?

        def __multi_get_events(thread_event_id):  # for threading
            try:
                event_object_dict[thread_event_id] = self.get_event_object(thread_event_id)
            except Exception as e:
                errors.append(e.message)
                pass

        for i in self.event_ids:
            t = threading.Thread(target=__multi_get_events, args=(i,))
            threads.append(t)
            t.start()
        for _thread in threads:
            _thread.join()
        return event_object_dict

    def get_event_summary(self):
        return EventsPacketSummary(self.Events)


class EventsPacketSummary(object):
    """Belongs to Incidents.events_summary"""
    def __init__(self, events_list):
        #self.events_list = events_list  # this is a list of the events objects; Incidents.events
        self.breakdown = ''  # JSON breakdown: signature->host->response_code->[event_ids]
        self.summary = ''  # object --> PacketSummarySummary
        self.get_events_info(events_list)  # sets breakdown to JSON amd summary to a list of EventsPacketSummary objects

    def get_events_info(self, events_list):
        """Iterates through the event objects and sets the global breakdown to JSON and the global summary to an
            EventPacketSummary object

            ###########################################################
            # structure
            ###########################################################
            # details: {
            #   <signatureName>: {
            #     <hostName>: {
            #        <responseCode>: [applicableEvents]
            #            }
            #         }
            #   <signatureName>: {
            #     <hostName>: {
            #        <responseCode>: [applicableEvents]
            #            }
            #         }
            #     }
            # summary': {
            #  'unique_signatures': unique_signatures,
            #  'unique_hosts': unique_hosts,
            #  'response_code_tally': response_code_tally
            #      }
            ###########################################################
        """
        #packet_info = {}  TODO:remove!
        packet_breakdown = {}
        unique_signatures = {}  # sig: [sig_applicable_events]
        unique_hosts = {}  # host: [hosts_applicable_events]
        response_code_tally = {}  # code: [code_applicable_events]
        # TODO!! This likely needs work as the summary was overriding itself and only returning final host with this alg
        for individual_event in events_list.values():  # this is a list of objects
            # TODO!!! This is obviously not correct and is dependent on the event object structure
            # TODO: event.event_payload.packet_details  <-- may be packet_details.request and response
            # do magic to pull out event summary
                try:
                    # details
                    signature = individual_event.event_details['signature_name']
                    host = individual_event.event_payload.packet_details.request_packet.host
                    response = individual_event.event_payload.packet_details.response_packet.response_code
                    individual_event_id = individual_event.event_id

                    if signature not in packet_breakdown.keys():
                        packet_breakdown[signature] = {host: {response: [individual_event_id]}}
                    elif host not in packet_breakdown[signature].keys():
                        packet_breakdown[signature][host] = {response: [individual_event_id]}
                    elif response not in packet_breakdown[signature][host].keys():
                        packet_breakdown[signature][host][response] = [individual_event_id]
                    else:
                        packet_breakdown[signature][host][response].append(individual_event_id)
                except KeyError:
                    continue  # packet failed to retrieve from get_event

                #######################################################
                # summary
                # signatures
                if signature not in unique_signatures.keys():
                    unique_signatures[signature] = [individual_event_id]
                else:
                    unique_signatures[signature].append(individual_event_id)
                # hosts
                if host not in unique_hosts.keys():
                    unique_hosts[host] = [individual_event_id]
                else:
                    unique_hosts[host].append(individual_event_id)
                # response codes
                if response not in response_code_tally.keys():
                    response_code_tally[response] = [individual_event_id]
                else:
                    response_code_tally[response].append(individual_event_id)
            #packet_info = {
            #    'summary': {
            #        'unique_signatures': unique_signatures,
            #        'unique_hosts': unique_hosts,
            #        'response_code_tally': response_code_tally
            #        }
            #    }
        self.breakdown = packet_breakdown
        self.summary = EventsSummarySummary(unique_signatures, unique_hosts, response_code_tally)


class EventsSummarySummary(object):
    # belongs to EventsPacketSummary
    def __init__(self, unique_sig, unique_host, unique_resp_code):
        self.unique_signatures = unique_sig  # dict --> sig: event_id
        self.unique_hosts = unique_host  # dict --> host: event_id
        self.response_code_tally = unique_resp_code  # dict --> code: event_id
