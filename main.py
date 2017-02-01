from alapi import alapi
import ConfigParser
import syslog
import argparse
import pprint
import threading
from src.cms_detector import scan
import json


def __print_cms(site, index):
    try:
        results_cms[index] = 'CMS Results for: {0}\n{1}\n{2}\n\n'.format(site, '-' * (17 + len(site)), scan(site))
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, 'Issue running cms_detector for: {0}; Error: {1}'.format(site, e.message))

config_file = 'config.cfg'
config = ConfigParser.RawConfigParser()

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--conf", default="config.cfg", help="Specify config File", metavar="FILE")
parser.add_argument("-c", "--customer", help="AlertLogic Customer ID")
parser.add_argument("-i", "--incident", help="AlertLogic Incident ID")
args = parser.parse_args()

incident_id = args.incident
customer_id = args.customer
config_file = args.conf

try:
    config.read(config_file)
except Exception as e:
    syslog.syslog(syslog.LOG_ERR, 'Failed to Read Config File: {0}\n{1}'.format(config_file, e))
    exit(2)

try:
    username = str(config.get('Alert Logic', 'username'))
    password = str(config.get('Alert Logic', 'password'))
    api_key = str(config.get('Alert Logic', 'api_key'))
except TypeError as e:
    syslog.syslog(syslog.LOG_ERR, 'Issue parsing credentials; verify config file: {0}\n{1}'.format(config_file, e))
    exit(2)

results = alapi.Incident(incident_id, customer_id, api_key, username, password)

pp = pprint.PrettyPrinter(indent=4)


unique_hosts = results.to_json()["events_summary"]["event_summary"]["unique_hosts"].keys()

# created list for CMS Results
results_cms = [{} for x in unique_hosts]
threads = []
i = 0
for unique_host in unique_hosts:
    t = threading.Thread(target=__print_cms, args=(unique_host, i, ))
    i += 1
    threads.append(t)
    t.start()
for thread in threads:
    thread.join()

results_json = results.to_json()
results_json["cms"] = results_cms

r = json.dumps(results_json)

#pp.pprint(results_json)
print (r)

