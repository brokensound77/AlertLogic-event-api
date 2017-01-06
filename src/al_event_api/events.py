

class Events(object):
    def __init__(self, event_id, url, details, signature_details, payload, event_summary):
        self.event_id = event_id
        self. url = url
        self.details = ''  # object ...change to dict?
        self.signature_details = ''  # object  ...change to dict?
        self. payload = ''  # object --> EventPayload
        self.event_summary = ''  # object --> EventsPacketSummary

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


