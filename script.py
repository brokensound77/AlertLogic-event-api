#!/usr/bin/env python
""" Script to query the API directly for """

import argparse
import al_api


def get_parameters():
    parser = argparse.ArgumentParser(description='script to test functionality of the al_event_api')
    parser.add_argument('customer_id', default='all_children', help='AL customer id')
    parser.add_argument('incident_id', help='AL incident id')
    # incident_id**
    parser.add_argument('-p', '--password')
    # event_number
    parser.add_argument('-p', '--password')
    # classification
    parser.add_argument('-p', '--password')
    # dest_addr
    parser.add_argument('-p', '--password')
    # dest_port
    parser.add_argument('-p', '--password')
    # signature
    parser.add_argument('-p', '--password')
    # source_port
    parser.add_argument('-p', '--password')
    # source_addr
    parser.add_argument('-p', '--password')
    # request_host
    parser.add_argument('-p', '--password')
    # request_restful_call
    parser.add_argument('-p', '--password')
    # response_code
    parser.add_argument('-p', '--password')
    # sig_id
    args = parser.parse_args()