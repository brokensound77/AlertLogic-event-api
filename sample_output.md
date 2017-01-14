```
Customer ID: 123456
Incident ID: 987654321
Incident Details: 
[   {   u'acknowledge_status': u'Acknowledged - Completed Analysis',
        u'acknowledged_by': 11111,
        u'acknowledged_date': 1484229335,
        u'attackers': [u'12.34.56.78'],
        u'begin_date': 1484228700,
        u'class_name': u'application-attack',
        u'closed_by': None,
        u'closed_date': None,
        u'closed_type': 0,
        u'correlation_end_date': 1484325100,
        u'correlation_start_date': 1481142300,
        u'create_date': 1489029334,
        u'created_by': 0,
        u'customer_id': 123456,
        u'customer_name': u'Example Widget Company',
        u'description':  'The attack was very bad and h4x0rs infiltrated. Do something...
        u'devices': [   {   u'device_id': u'55555',
                            u'name': u'widget-computer-1',
                            u'sensor_id': 55555}],
        u'end_date': 1484128700,
        u'escalated': 1,
        u'event_ids': [13579, 24680],
        u'evolution_root': 987654321,
        u'evolution_tree': {   u'evolved_from': [], u'incident_id': 987654321},
        u'evolved_to': None,
        u'geoip': {   u'12.34.56.78': {   u'area_code': 999,
                                            u'city': u'Paris',
                                            u'country_code': u'FR',
                                            u'country_code3': u'FRA',
                                            u'country_name': u'France',
                                            u'dma_code': 050,
                                            u'latitude': 119.27340000000001,
                                            u'longitude': -103.7133,
                                            u'postal_code': u'88888',
                                            u'region': u'UN'}},
        u'incident_id': 987654321,
        u'is_proxy': True,
        u'last_modified_date': 1481129335,
        u'modified_by': None,
        u'num_evts': 2,
        u'open': 1,
        u'reopen_date': None,
        u'summary': u'Joomla 0Day Serialized Object Injection RCE from 12.34.56.78\n',
        u'threat_rating': u'Medium',
        u'vector': {   u'sub_type': u'joomlaua', u'type': u'webapp_attack'},
        u'victims': [u'10.11.12.13']}]

Summary of Events 
	Summary Breakdown: 
{   'AL Joomla User Agent/XFF Header Serialized Object Injection RCE 0day Attempt': {   'www.example.com': {   '200': [ 13579,
																														24680]}}}
	Totals: 
		Unique Signatures: 
	{   'AL Joomla User Agent/XFF Header Serialized Object Injection RCE 0day Attempt': [ 13579,
																						  24680]}
		Unique Hosts: 
	{   'www.example.com': [13579, 24680]}
		Response Code Tally: {   '200': [13579, 2468]}

Events: 
Event ID: 13579
Event Link: 
https://url.for.alertlogic.com/event.php?id=XXXXX&customer_id=XXXXXX&screen=event_monitor&filter_id=0
Event Details: 
{   'classification': 'web-application-attack',
    'dest_addr': '10.11.12.13',
    'dest_port': '80',
    'protocol': 'tcp',
    'sensor': 'widget-computer-1',
    'severity': '0',
    'signature_name': 'AL Joomla User Agent/XFF Header Serialized Object Injection RCE 0day Attempt',
    'source_addr': '12.34.56.78',
    'source_port': '28790'}
Signature Details: 
{   'sig_id': '100213',
    'sig_rule': 'alert tcp $EXTERNAL_NET any -&gt; $HTTP_SERVERS $HTTP_PORTS (msg:&quot;AL Joomla<br />User Agent/XFF Header Serialized Object Injection RCE 0day Attempt&quot;;<br />flow:to_server,established; content:&quot;}__&quot;; http_header;<br />content:&quot;O:21:|22|JDatabaseDriverMysqli|22|&quot;; http_header;<br />content:&quot;O:17:|22|JSimplepieFactory|22|&quot;; http_header;<br />reference:url,freebuf.com/vuls/89754.html; classtype:web-application-attack;<br />sid:1100085;  tag:session,5,packets; rev:1;)'}
Event Payload: 
	Packet Details: 
		Request Packet: 
			Restful Call: GET
			Protocol: HTTP/1.1
			Host: example.com
			Resource: /example
			Full URL: example.com/example/
		Response Packet: 
			Response Code: 200
			Response Message: OK
Full Payload: 

GET / HTTP/1.1
Host: example.com
Connection: Keep-Alive
Accept-Encoding: gzip
CF-IPCountry: US
X-Forwarded-For: 24.68.10.10
X-Forwarded-Proto: http
Accept: */*
User-Agent: I-swear-I-am-not-using-python-to-scan-you

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 22 Mar 2015 11:41:11 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: example_init=0; expires=Fri, 12-Mar-2015 13:45:51 GMT; path=/; domain=example.com
X-Powered-By: PleskLin

<!DOCTYPE html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 50px;
        background-color: #fff;
        border-radius: 1em;
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        body {
            background-color: #fff;
        }
        div {
            width: auto;
            margin: 0 auto;
            border-radius: 0;
            padding: 1em;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is established to be used for illustrative examples in documents. You may use this
    domain in examples without prior coordination or asking for permission.</p>
    <p><a href="http://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>



Event ID: 2468
Event Link: 
https://url.for.alertlogic.com/event.php?id=XXXXX&customer_id=XXXXXX&screen=event_monitor&filter_id=0
Event Details: 
{   'classification': 'web-application-attack',
    'dest_addr': '10.11.12.13',
    'dest_port': '80',
    'protocol': 'tcp',
    'sensor': 'widget-computer-1',
    'severity': '0',
    'signature_name': 'AL Joomla User Agent/XFF Header Serialized Object Injection RCE 0day Attempt',
    'source_addr': '12.34.56.78',
    'source_port': '28790'}
Signature Details: 
{   'sig_id': '100213',
    'sig_rule': 'alert tcp $EXTERNAL_NET any -&gt; $HTTP_SERVERS $HTTP_PORTS (msg:&quot;AL Joomla<br />User Agent/XFF Header Serialized Object Injection RCE 0day Attempt&quot;;<br />flow:to_server,established; content:&quot;}__&quot;; http_header;<br />content:&quot;O:21:|22|JDatabaseDriverMysqli|22|&quot;; http_header;<br />content:&quot;O:17:|22|JSimplepieFactory|22|&quot;; http_header;<br />reference:url,freebuf.com/vuls/89754.html; classtype:web-application-attack;<br />sid:1100085;  tag:session,5,packets; rev:1;)'}
Event Payload: 
	Packet Details: 
		Request Packet: 
			Restful Call: GET
			Protocol: HTTP/1.1
			Host: example.com
			Resource: /example
			Full URL: example.com/example/
		Response Packet: 
			Response Code: 200
			Response Message: OK
Full Payload: 

GET / HTTP/1.1
Host: example.com
Connection: Keep-Alive
Accept-Encoding: gzip
CF-IPCountry: US
X-Forwarded-For: 24.68.10.10
X-Forwarded-Proto: http
Accept: */*
User-Agent: I-swear-I-am-not-using-python-to-scan-you

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 22 Mar 2015 11:41:11 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: example_init=0; expires=Fri, 12-Mar-2015 13:45:51 GMT; path=/; domain=example.com
X-Powered-By: PleskLin

<!DOCTYPE html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 50px;
        background-color: #fff;
        border-radius: 1em;
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        body {
            background-color: #fff;
        }
        div {
            width: auto;
            margin: 0 auto;
            border-radius: 0;
            padding: 1em;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is established to be used for illustrative examples in documents. You may use this
    domain in examples without prior coordination or asking for permission.</p>
    <p><a href="http://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
```
