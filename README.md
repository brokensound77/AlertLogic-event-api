# AlertLogic-event-api

Client side API for interacting with Alert Logic events (from threat manager). The Alert Logic API does not offer any way to interact with events directly.

##Installation:
`pip install .`

It is advisable to us a virtualenv

##Simple usage:
```python
AlertLogic = AlPseudoAPI(username, password)
```

###Getting Events
```python
event_list = []  # list of event IDs
results = AlertLogic.get_events(customer_id, event_list, summary=True)
```

If you have and API key, you can use the built in method to populate the events list
```python
events = AlertLogic.get_events_from_incident(customer_id, incident_id, api_key)
results = AlertLogic.get_events(customer_id, events, summary=True)
```


