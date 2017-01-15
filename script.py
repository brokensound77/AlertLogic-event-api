#!/usr/bin/env python
""" Script to query the API directly for """

import argparse
import ConfigParser
import src.alapi as al_api

description = ('This script is used to implement the al_api in a quick manner. The script will run on the incident'
               'provided and will return only those events matching ALL the parameters passed. The default is to print'
               'out these events.')
parser = argparse.ArgumentParser(description=description)
parser.add_argument('incident_id', help='AL incident id')
parser.add_argument('customer_id', default='all_children', help='AL customer id')
parser.add_argument('api_key')
parser.add_argument('username')
parser.add_argument('password')
parser.add_argument('-eid', '--event_number')
parser.add_argument('-ecl', '--classification')
parser.add_argument('-eda', '--event_destination_address')
parser.add_argument('-edp', '--event_destination_port')
parser.add_argument('-esn', '--event_signature')
parser.add_argument('-esp', '--event_source_port')
parser.add_argument('-esa', '--event_source_address')
parser.add_argument('-erh', '--event_request_host')
parser.add_argument('-ert', '--event_restful_call')
parser.add_argument('-erc', '--event_response_code')
parser.add_argument('-esid', '--event_signature_id')
args = parser.parse_args()

incident = al_api.Incident(args.incident_id, args.customer_id, args.api_key, args.username, args.password)
