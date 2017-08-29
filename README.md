# AlertLogic-event-api

Client side API for interacting with Alert Logic incidents and events (from threat manager). Alert Logic does not offer an API or any way to interact with events directly. This API also provides additional contextual summary information of all of the events tied to the specific incident.

## Requirements
The only requirement is requests

(and of course you need AL credentials and an API key)

## Simple usage:
```python
from alapi import alapi

incident = alapi.Incident(incident_id, customer_id, api_key, username, password)
print incident
```
Example output (with dummy data) included - [sample_output](https://github.com/brokensound77/AlertLogic-event-api/blob/master/sample_output.md)

for full API documentation, refer to the [wiki](https://github.com/brokensound77/AlertLogic-event-api/wiki/API-Documentation)

***
## Data Captured

The table below shows all of the data that can be gathered with this API. Additionally, all of the incident details are also pulled via the actual Alert Logic Incident API and provided as well. To see this, go [here](https://docs.alertlogic.com/developer/).

(All items are per event, except for summary events, which are rolled up into the incident object, indicated by a \*)  

| Data                   | Example           | Description                                          | 
|------------------------|:-----------------:|:-----------------------------------------------------|
| response_code_tally\*  | `'200': [14608, 14621]` | total of the packet response codes by event          
| unique_hosts\*         | `'example.net': [14608, 14621]` | all hosts targeted in the incident
| unique_signatures\*    | `'AL Joomla...': [14608, 14621]` | all signatures applicable to the incident
| summary_breakdown\*    | `'AL Joomla...': {'example.net': {'200': [14608, 14621]}}` | events by response by host by sig
| classification         | `'web-application-attack'` | type of attack
| dest_addr              | `'123.45.78.90'` | destination IP address
| dest_port              | `'12345'` | destination port
| protocol               | `'tcp'` | protocol
| sensor                 | `'example-sensor-12345-ngtm'` | name of sensor which captured the data
| severity               | `'50'` | severity of the attack
| signature_name         | `'Al Joomla...'` | the name of the actual signature
| source_addr            | `'123.45.78.90'` | source IP address
| source_port            | `'3215'` | source port
| full_url               | `'www[.]example.net/hax/your/page'` | full url which the attack was targeting
| host                   | `'example.net'` | hostname targeted by the attack
| protocol               | `'HTTP/1.1'` | protocol used in the attack
| resource               | `'/hax/your/page'` | the resource targeted in the attack
| restful_call           | `'POST'` | the restful call used in the attack
| response_code          | `'200'` | response code of the host being attacked
| response_message       | `'OK'` | response message of the host being attacked
| full_payload           | _entire packet contents_ | the full payload of the packets captured in the attack (request and response)
| decompressed           | _decompressed gzip data_ | decompressed gzip data, if present
| event_url              | _full AL Event URL_ | url for the event
| sig_id                 | `'100211'` | signature ID applicable to the event
| sig_rule               | `'alert any any -> any any...'` | the full signature rule which triggered the event
