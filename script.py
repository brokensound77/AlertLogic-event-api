#!/usr/bin/env python
""" Script to query the API directly for """

import argparse
import al_api


parser = argparse.ArgumentParser(description='script to implement the al_api')
parser.add_argument('incident_id', help='AL incident id')
parser.add_argument('customer_id', default='all_children', help='AL customer id')
parser.add_argument('-a', '--api_key')
parser.add_argument('-u', '--username')
parser.add_argument('-p', '--password')
parser.add_argument('-iid', '--incident-id')
parser.add_argument('-eid', '--event-number')
parser.add_argument('-ecl', '--classification')
parser.add_argument('-eda', '--event-destination-address')
parser.add_argument('-edp', '--event-destination-port')
parser.add_argument('-esn', '--event-signature')
parser.add_argument('-esp', '--event-source-port')
parser.add_argument('-esa', '--event-source-address')
parser.add_argument('-erh', '--event-request-host')
parser.add_argument('-ert', '--event-restful-call')
parser.add_argument('-erc', '--event-response-code')
parser.add_argument('-esid', '--event-signature-id')
args = parser.parse_args()


