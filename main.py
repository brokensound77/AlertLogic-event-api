from alapi import alapi
import ConfigParser
import syslog
import argparse

config_file = 'config.cfg'
config = ConfigParser.RawConfigParser()

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--conf", default="config.cfg", help="Specify config File", metavar="FILE")
parser.add_argument("-c", "--customer", help="AlertLogic Customer ID")
parser.add_argument("-i", "--incident", help="AlertLogic Incident ID")
args = parser.parse_args()

incident_id = args.incident
customer_id = args.customer

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

incident = alapi.Incident(incident_id, customer_id, api_key, username, password)

print incident.to_json()
