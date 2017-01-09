# quick script to test api functionality

import pprint
import argparse
from getpass import getpass
try:
    from al_event_api import AlPseudoAPI
except ImportError:
    from sys import stderr
    stderr.write('API was imported from local source; check pip installation')
    from al_event_api import AlPseudoAPI
    

parser = argparse.ArgumentParser(description='script to test functionality of the al_event_api')
parser.add_argument('customer_id', default='all_children', help='AL customer id')
parser.add_argument('incident_id', help='AL incident id')
parser.add_argument('-a', '--api_key')
parser.add_argument('-u', '--username')
parser.add_argument('-p', '--password')

args = parser.parse_args()
incident_id = args.incident_id
customer_id = args.customer_id
if args.api_key:
    api_key = args.api_key
else:
    api_key = raw_input('AL api_key: ')
if args.username:
    username = args.username
else:
    username = raw_input('AL username: ')
if args.password:
    password = args.password
else:
    password = getpass(prompt='AL password: ')


AlertLogic = AlPseudoAPI(username, password)
events = AlertLogic.get_events_from_incident(customer_id, incident_id, api_key)
results = AlertLogic.get_events(customer_id, events, summary=True)

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(results)
