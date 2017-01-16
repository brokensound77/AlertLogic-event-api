# AlertLogic-event-api

Client side API for interacting with Alert Logic incidents and events (from threat manager). Alert Logic does not offer an API or any way to interact with events directly. This API also provides additional contextual summary information of all of the events tied to the specific incident.

##Requirements
The only requirements at this moment is requests

##Installation:
`pip install .`

It is advisable to install within a virtualenv

##Simple usage:
```python
from src import al_api

incident = al_api.Incident(incident_id, customer_id, api_key, username, password)
print incident
```
Example output (with dummy data) included - [sample_output](https://github.com/brokensound77/AlertLogic-event-api/blob/development_version2_oop/sample_output.md)

for full API documentation, refer to the wiki (coming soon)
__________________
#Using the old API 
__________________
(now v1_api)

##Simple usage:
```python
from v1_api import AlPseudoAPI

AlertLogic = AlPseudoAPI(username, password)
```

####Getting Events
To get a single event
```python
result = AlertLogic.get_event(customer_id, incident_id)
```
Getting multiple events
```python
event_list = ['12345', '67890', '13579', '24680']  # list of event IDs
results = AlertLogic.get_events(customer_id, event_list)
```
If you have and API key, you can use the built in method to populate the events list
```python
events = AlertLogic.get_events_from_incident(customer_id, incident_id, api_key)
results = AlertLogic.get_events(customer_id, events)
```
For a summary of the events passed, you can set `summary=True`
```python
results = AlertLogic.get_events(customer_id, events, summary=True)
```
