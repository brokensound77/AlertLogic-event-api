import re
import pprint




pp = pprint.PrettyPrinter(indent=4)


def header_parse(payload):
    """
    Dynamically parses all headers. Splits the payload into 3 sections by \n\r (0d0a) to separate request headers,
    response headers, and response body. Searches both header sections for individually passed headers and sets them as
    key-value pairs
    """
    headers = {
        'request_headers': {},
        'response_headers': {},
        #'payload_response_body': ''
    }
    payload_split = payload.split('\n\r', 2)  # request, response, body
    if len(payload_split) != 3:
        return headers
    count = 1
    for item in payload_split[:2]:
        if count == 1:
            header_type = 'request'
        elif count == 2:
            header_type = 'response'
        for line in item.split('\n'):
            header = re.match('(?P<header>[\w-]+)?: (?P<value>.+)', line)
            if header is not None and len(header.groups()) == 2:
                try:
                    # print len(header.groups())
                    headers[header_type + '_headers'][header.group('header')] = header.group('value').strip()
                except Exception:
                    continue
        count += 1
    #headers['payload_response_body'] = payload_split[2]
    return headers