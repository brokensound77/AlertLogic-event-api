"""
All events and incidents can be directly retrieved or set as objects. Must instantiate with Alert Logic username and
password and can optionally pass an API key as well (for incident API interaction). If the API key is not passed, it
can be subsequently set using the set_api_key method.
"""
import requests
#from bs4 import BeautifulSoup
import re
import binascii
import gzip
#import zlib  #remove?
import os
import subprocess
import time
from string import printable
import threading
import traceback


def get_event(username, password, customer_id, event_number, api_key=None):
    return AlPseudoAPI(username, password, api_key).get_event(customer_id, event_number)


def get_events(username, password, customer_id, event_list, api_key=None, summary=False):
    return AlPseudoAPI(username, password, api_key).get_events(customer_id, event_list, summary)


class AlPseudoAPI(object):

    purpose = 'Alert Logic Pseudo API for events'

    def __init__(self, username, password, api_key=None):
        self.__alogic = requests.Session()
        self.__login_al(username, password)
        self.__api_key = api_key
        self.event = ''
        self.events = list()
        self.incident = ''
        self.incidents = list()

    def __login_al(self, al_un, al_pw):
        login_params = {#'SMENC': 'ISO-8859-1',
                        'SMLOCALE': 'US-EN',
                        'target': '-SM-/',
                        'SMAUTHREASON': 0,
                        'user': al_un,
                        'password': al_pw
                        }
        r = self.__alogic.post('https://console.clouddefender.alertlogic.com/forms/login2.fcc', data=login_params)
        if r.status_code != 200:
            raise Exception('Failed to authenticate. Status code: {0}\nException: {1}'.format(r.status_code, r.reason))
        return

    def __gz_handler(self, event_id, converted_hex):
        """ Detects and decompresses gzipped hex """
        #TODO: make this public for use with the raw interactive methods????
        hold_hex = ''
        hold_bin = ''
        decompressed_data = '\n[*] Decompressed data detected'
        if '0d0a0d0a1f8b08' in converted_hex:  # 0d0a0d0a-packet header delineation, 1f8b08-gz signature
            hold_hex = converted_hex[converted_hex.find('0d0a0d0a1f8b08') + 8:]
        elif '1f8b08' in converted_hex:
            hold_hex = converted_hex[converted_hex.find('1f8b08'):]
        else:
            return ''
        if len(hold_hex) <= 20:  # per RFC1952, gzip header must contain at least 10 bytes (20 hex characters)
            decompressed_data += '\n[!] Unable to decompress. Too much missing data\n'
            return decompressed_data
        try:
            hold_bin = binascii.a2b_hex(hold_hex)
        except TypeError:
            decompressed_data += '\n[!] Potential zipped data detected but unable to convert - check event'
            return decompressed_data
        #############################################
        # TODO: Possibly implement
        #############################################
        #gz_handler = gzip.GzipFile(fileobj=hold_bin)
        #try:
            #decompressed_data += gz_handler.read()
            #return decompressed_data
        #############################################
        tmp_file_name = '/tmp/{0}_{1}.tmp'.format(event_id, time.time())  # unique name prevents overriding with threading
        with open(tmp_file_name, 'wb') as outfile:
            outfile.write(hold_bin)
        try:
            with gzip.open(tmp_file_name, 'rb') as f:
                decompressed_data += f.read()
        except Exception as e:
            decompressed_data += '\n[!] Missing zip data detected | Adding partial contents\n\n'
            output = subprocess.Popen(["zcat", tmp_file_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            if output is None:
                # log error message with output[1]
                decompressed_data += '\n[!] Something went wrong with zcat output - check event'
            else:
                decompressed_data += output[0]
        if os.path.exists(tmp_file_name):
            os.remove(tmp_file_name)
        # would be really awesome to be able to decompress incomplete with zlib instead of fooling with zcat
        #return zlib.decompress(hold_bin, 16+zlib.MAX_WBITS)
        return decompressed_data

    def set_api_key(self, api_key):
        """ used to globally set api key persistently for multiple incident api calls """
        self.__api_key = api_key

    def __get_api_key(self):
        if self.__api_key is None:
            raise Exception('API key must be passed, instantiated, or set using set_api_key!')
        return self.__api_key

    def __packet_analysis(self, payload): #request_payload, response_payload):
        """

        :param payload (str):
        :return:
        """
        restful_call = ''
        protocol = ''
        host = ''
        resource = ''
        response_code = 'None parsed'
        response_message = 'None parsed'
        # request
        rex_request = re.search(
            '(?P<restful_call>GET|POST|HEAD|TRACE|PUT)\s(?P<resource>[\S.]*)\s(?P<protocol>\S*)', payload)
        if rex_request:
            restful_call = rex_request.group('restful_call')             # GET
            resource = rex_request.group('resource')                     # /admin/blah
            protocol = rex_request.group('protocol')                     # HTTP/1.1
        rex_host = re.search('host:\s(?P<host>[\w\.-]*)', payload, re.I)  # www.example.com
        if rex_host:
            host = rex_host.group('host')
        # response
        rex_response = re.search('HTTP/[\d\.]+\s(?P<code>\d{3})\s(?P<message>[\w ]*)', payload)
        if rex_response:
            response_code = rex_response.group('code')                   # 302
            response_message = rex_response.group('message')             # Found
        packet_details = {
            'request_packet': {
                'restful_call':     restful_call,
                'protocol':         protocol,
                'host':             host,
                'resource':         resource,
                'full_url':         host + resource
                },
            'response_packet': {
                'response_code':    response_code,
                'response_message': response_message
                }
            }
        return packet_details

    def __packet_summary(self, event_data_list):
        packet_info = {}
        packet_analysis = {}
        unique_signatures = {}  # sig: [sig_applicable_events]
        unique_hosts = {}  # host: [hosts_applicable_events]
        response_code_tally = {}  # code: [code_applicable_events]
        for i in event_data_list:
            try:
                # details
                signature = i['details']['signature_name']
                host = i['payload']['packet_details']['request_packet']['host']
                response = i['payload']['packet_details']['response_packet']['response_code']
                event = i['event']

                if signature not in packet_analysis.keys():
                    packet_analysis[signature] = {host: {response: [event]}}
                elif host not in packet_analysis[signature].keys():
                    packet_analysis[signature][host] = {response: [event]}
                elif response not in packet_analysis[signature][host].keys():
                    packet_analysis[signature][host][response] = [event]
                else:
                    packet_analysis[signature][host][response].append(event)
            except KeyError:
                continue  # packet failed to retrieve from get_event

            #######################################################
            # summary
            # signatures
            if signature not in unique_signatures.keys():
                unique_signatures[signature] = sig_applicable_events = [i['event']]
            else:
                unique_signatures[signature].append(i['event'])
            # hosts
            if host not in unique_hosts.keys():
                unique_hosts[host] = hosts_applicable_events = [i['event']]
            else:
                unique_hosts[host].append(i['event'])
            # response codes
            if response not in response_code_tally.keys():
                response_code_tally[response] = code_applicable_events = [i['event']]
            else:
                response_code_tally[response].append(i['event'])
        packet_info = {
            'details': [packet_analysis],
            'summary': {
                'unique_signatures': unique_signatures,
                'unique_hosts': unique_hosts,
                'response_code_tally': response_code_tally
                }
            }
        ###########################################################
        # packet_analysis structure
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
        return packet_info

    def __get_signature_details(self, sig_id):
        primary_ur = 'https://scc.alertlogic.net/ids_signature/{0}'.format(sig_id)
        # backup in the event of a permissions issue to the primary url
        backup_url = 'https://console.clouddefender.alertlogic.com/signature.php?sid={0}'.format(sig_id)
        r = self.__alogic.get(primary_ur)
        winner = 'primary'

        if r.status_code != 200:
            r = self.__alogic.get(backup_url)
            winner = 'backup'

            if r.status_code != 200:
                return 'Failed to retrieve signature details :('

        if winner == 'primary':
            sig_type = ''
            sig_rule = ''
            sig_references = ''
            sig_cve = ''
            sig_date = ''
            # logic for info
            # TODO: There is a problem with the regex for the sig_cve
            sig_details_search = re.search('<td>Classtype:\s*</td>[\s\n]+<td>(?P<sig_type>.*)</td>|'
                                           '<td>Detection:\s*</td>[\s\n]+<td>(?P<sig_rule>.*)</td>|'
                                           '<td>References:\s*</td>[\s\n]+<td>(?P<sig_references>.*)</td>|'
                                           '<td>Vulnerabilities:\s*</td>[\s\n]+<td>(?P<sig_cve>.*)[\s\n]*</td>|'
                                           '<td>Date\sAdded:\s*</td>[\s\n]+<td>(?P<sig_date>.*)</td>', r.text)
            if sig_details_search is not None:
                # TODO: Will need to rework the exception handling logic here!
                try:
                    sig_type = sig_details_search.group('sig_type')
                except IndexError:
                    pass
                try:
                    sig_rule = sig_details_search.group('sig_rule')
                except IndexError:
                    pass
                try:
                    sig_references = sig_details_search.group('sig_references')
                except IndexError:
                    pass
                try:
                    sig_cve = sig_details_search.group('sig_cve')
                except IndexError:
                    pass
                try:
                    sig_date = sig_details_search.group('sig_date')
                except IndexError:
                    pass

            sig_details = {
                'sig_id': sig_id,
                'sig_type': sig_type,
                'sig_rule': sig_rule,
                'sig_references': sig_references,
                'sig_cve': sig_cve,
                'sig_date': sig_date
            }
            return sig_details

        elif winner == 'backup':
            sig_rule = ''
            # logic for info
            sig_details_search = re.search('<th>Signature\sContent</th>[\s\n]+<td>(?P<sig_rule>.*)</td>', r.text)
            if sig_details_search is not None:
                sig_rule = sig_details_search.group('sig_rule')

            sig_details = {
                'sig_id': sig_id,
                'sig_rule': sig_rule
                }
            return sig_details

    def set_event(self, customer_id, event_number):
        self.event = self.get_event(customer_id, event_number)

    def get_event_NEW(self):
        """ Use BeautifulSoup """
        return

    def set_events(self, customer_id, event_list, append=False):
        """ used to globally sent events list """
        if append:
            for i in event_list:
                self.events.append(self.get_events(customer_id, i))
        else:
            del self.events
            for i in event_list:
                self.events.append(self.get_events(customer_id, i))

    def get_event(self, customer_id, event_number):
        """
        Retrieves the event page, parses some descriptive fields for metadata, and cleans up then reconstructs
        the payload data. Returns
        """
        full_event = {}
        signature_details = {}
        source_address = ''
        dest_address = ''
        source_port = ''
        dest_port = ''
        signature_name = ''
        sensor = ''
        protocol = ''
        classification = ''
        severity = ''
        decompressed = ''
        packet_details = ''
        event_id = str(event_number)
        customer_id = str(customer_id)
        screen = 'event_monitor'
        filter_id = '0'
        event_url = 'https://console.clouddefender.alertlogic.com/event.php?id={0}&customer_id={1}&screen={2}&filter_id={3}'.format(
                event_id, customer_id, screen, filter_id)
        r = self.__alogic.get(event_url, allow_redirects=False)
        #print r.status_code  # TODO: Add some exception handling here...try 3 times??? raise error? skip with message?
        if r.status_code != 200:
            #return 'Failed to retrieve event #{0}.'.format(event_id)
            raise Exception('Failed to retrieve event #{0}. Status code: {1}\nReason: {2}'.format(
                event_id, r.status_code, r.reason))
        tmp_raw_page = str(r.text)
        ###################################################################
        # REGEX Event Details
        ###################################################################
        rex = re.compile(
            "var source_addr = '(?P<source_address>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})';\n" +
            "var dest_addr = '(?P<dest_address>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})';\n" +
            "var source_port = '(?P<source_port>\d{0,5})';\n" +
            "var dest_port = '(?P<dest_port>\d{0,5})';\n" +
            "var signature_name = '(?P<signature_name>[=/_()\.\w\s-]*)';\n" +
            "var sensor = '(?P<sensor>[\w\d-]*)';\n" +
            "var protocol = '(?P<protocol>\w*)';\n" +
            "var classification = '(?P<classification>[\w\s-]*)';\n" +
            "var severity = '(?P<severity>\d*)';\n")
        rex_results = rex.search(tmp_raw_page)
        if rex_results:
            source_address = rex_results.group('source_address')
            dest_address = rex_results.group('dest_address')
            source_port = rex_results.group('source_port')
            dest_port = rex_results.group('dest_port')
            signature_name = rex_results.group('signature_name')
            sensor = rex_results.group('sensor')
            protocol = rex_results.group('protocol')
            classification = rex_results.group('classification')
            severity = rex_results.group('severity')
        ########################################
        sig_id_search = re.search('<strong><a\shref="/signature.php\?[\w=&]*sid=(?P<sig_id>\d+).+', tmp_raw_page)
        if sig_id_search is not None:
            sig_id = sig_id_search.group('sig_id')
            # TODO: this should break into its own thread that joins right before the full event {} assembly
            signature_details = self.__get_signature_details(str(sig_id))
        ##################################################################
        ##################################################################
        start_parse = str(r.text).find('<td>Signature: ') - 18
        end_parse = str(r.text).find('<table id="cache_table" style="display: none;">')
        parsed_html = str(r.text[start_parse:end_parse])
        raw_hex = ''
        for line in parsed_html.splitlines(True):
            hexstring = re.match(r'.*(0x[\da-f]{4}:[\s\da-f]+)\W', line.strip())
            if hexstring is not None:
                raw_hex += hexstring.string + '\n'
        # print raw_hex  # preserve this to print raw hex formatted
        raw2 = re.findall(r'(?<=0x[\da-fA_F]{4}:\s)\b[\da-fA-F]{4}\b|(?<=[\da-fA-F]{4}\s)\b[\da-fA-F]{4}\b', raw_hex)
        raw3 = ''  # this is the TRUE raw hex of the packets
        for chunk in raw2:
            raw3 += chunk
        full_payload1 = '{0}'.format(raw3.decode('hex').decode('ascii', 'ignore'))  # what is lost with ignore vs 'replace'
        full_payload = ''.join([c for c in full_payload1 if c in printable])
        packet_details = self.__packet_analysis(full_payload)
        decompressed = self.__gz_handler(event_id, raw3)
        full_event = {
            'event':                    event_id,
            'url':                      event_url,
            'details': {
                'source_addr':          source_address,
                'dest_addr':            dest_address,
                'source_port':          source_port,
                'dest_port':            dest_port,
                'signature_name':       signature_name,
                'signature_details':    signature_details,
                'sensor':               sensor,
                'protocol':             protocol,
                'classification':       classification,
                'severity':             severity
                },
            'payload': {
                'full_payload':         full_payload,
                #'request':             request_payload, #TODO: maybe
                #'response':            response_payload,
                'packet_details':       packet_details,
                'decompressed':         decompressed
                }
            }
        return full_event

    def get_events(self, customer_id, event_list, summary=False):
        """
        Iterates (threaded) through all of the events provided. If analyze is set to true, analysis data is sent in a
            JSON structure as the second item of a tuple. Exceptions are stored in an 'errors' list
        :param customer_id:
        :param event_list:
        :param summary: setting this to true will execute summary analystics on all of the packets and return a tuple
            of the list of events and a json object of the analysis
        :return:
        """
        local_events = []
        threads = []
        errors = []

        def __multi_get_events(item):  # for threading
            try:
                local_events.append(self.get_event(customer_id, item))
            except Exception as e:
                errors.append(e.message)
                pass

        for i in event_list:
            t = threading.Thread(target=__multi_get_events, args=(i,))
            threads.append(t)
            t.start()
        for _thread in threads:
            _thread.join()
        if summary:
            packet_analysis = self.__packet_summary(local_events)
            return local_events, packet_analysis
        else:
            return local_events

    def set_incident(self, customer_id, incident_id):  # keep this? persistent global incident?
        self.incident = zip(customer_id, incident_id)

    def set_incidents(self, customer_id, incident_list, append=False):
        if append:
            for i in incident_list:
                self.incidents.append(zip(customer_id, i))
        else:
            del self.incidents  # necessary?
            for i in incident_list:
                self.incidents.append(zip(customer_id, i))

    def get_events_from_incident(self, customer_id, incident_id, api_key=None, persist=False):
        """ Accepts an incident (either from global object or from incident_id for retrieval) and returns all events
        associated the incident
        :param customer_id (str): This is the actual customer ID as defined by Alert Logic
        :param incident_id (str): Alert Logic incident ID
        :param api_key (str): API key associated with the account; This can also be globally set for persistence using
            set_api_key
        :param persist (str): When incidents are retrieved directly by passing the specified parameters, the global
            object 'incident' is not set by default. In order to properly set it, use the set_incident method. If the
            persist flag is set to True, then the incident object will be set with this call
        :return:
        """
        #TODO: whats the difference between customer_id and CID again? rax# vs al#??
        header = {'accept': 'application/json'}
        local_api_key = api_key if api_key is not None else self.__get_api_key()
        url = 'https://api.alertlogic.net/api/incident/v3/incidents?incident_id=' + incident_id + \
              '&customer_id=' + customer_id
        r = requests.get(url, headers=header, auth=(local_api_key, ''))
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

    def get_events_from_incidents(self, customer_id, incident_list, api_key=None, persist=False):
        """ Accepts a list of incidents (either from global objects or from incident_id for retrieval) and returns all
        events associated with each incident """
        events_from_incidents = list()
        for incident_id in incident_list:
            events_from_incidents.append(self.get_events_from_incident(customer_id, incident_id, api_key, persist))
        return events_from_incidents

    def raw_event_manipulator(self):
        """ Ability to directly interact with raw beautifulsoup object on an event """
        return

    def raw_session_manipulator(self):
        """ Ability to directly interact with raw request Session object """
        return
