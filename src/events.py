

from alertlogic import *

def to_json():
    return


def to_string():
    return


class Event(AlertLogic):
    def __init__(self, event_id, url, details, signature_details, payload, event_summary):
        self.event_id = event_id
        self.event_url = url
        self.event_details = '' # object ...change to dict?
        self.signature_details = ''  # object  ...change to dict?
        self.event_payload = ''  # object --> EventPayload
        self.event_summary = ''  # object --> EventsPacketSummary

    def set_event_details(self,
                      source_addr,
                      dest_addr,
                      source_port,
                      dest_port,
                      signature_name,
                      sensor,
                      protocol,
                      classification,
                      severity):

        event_details = {
            'source_addr': source_addr,
            'dest_addr': dest_addr,
            'source_port': source_port,
            'dest_port': dest_port,
            'signature_name': signature_name,
            'sensor': sensor,
            'protocol': protocol,
            'classification': classification,
            'severity': severity
            }
        self.event_details = event_details
        return

    def set_signature_details(self,
                            sig_id,
                            sig_type,
                            sig_rule,
                            sig_references,
                            sig_cve,
                            sig_date):

        sig_details = {
            'sig_id': sig_id,
            'sig_type': sig_type,
            'sig_rule': sig_rule,
            'sig_reference': list(sig_references),  # list?
            'sig_cve': sig_cve,
            'sig_date': sig_date
            }
        self.signature_details = sig_details

    def set_payload(self):
        return EventPayload()




###############################################################################
###############################################################################


class EventDetails(object):
    # convert to list and move to Events??
    def __init__(self):
        self.source_addr = ''
        self.dest_addr = ''
        self.source_port = ''
        self.dest_port = ''
        self.signature_name = ''
        self.sensor = ''
        self.protocol = ''
        self.classification = ''
        self.severity = ''


###############################################################################

class EventSignatureDetais(object):
    # convert to list and move to Events??
    def __init__(self):
        self.sig_id = ''
        self.sig_type = ''
        self.sig_rule = ''
        self.sig_references = ''  # list?
        self.sig_cve = ''
        self.sig_date = ''


###############################################################################

class EventPayload(object):
    # belongs to Events
    def __init__(self):
        self.full_payload = ''
        self.decompressed = ''
        self.raw_hex = ''  # TODO: keep?  # could be useful for signature rule compares
        self.packet_details = ''  # object --> RequestPacketDetails


class PacketDetails(object):
    # belongs to EventPayload
    def __init__(self):
        self.request_packet = ''  # object --> RequestPacketDetails
        self.response_packet = ''  # object --> ResponsePacketDetails


###############################################################################

class RequestPacketDetails(object):
    # belongs to PacketDetails
    def __init__(self):
        self.restful_call = ''
        self.protocol = ''
        self.host = ''
        self.resource = ''
        self.full_url = ''


class ResponsePacketDetails(object):
    # belongs to PacketDetails
    def __init__(self):
        self.response_code = ''
        self.response_message = ''


###############################################################################

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


