# AlertLogic-event-api

Client side API for interacting with Alert Logic events (from threat manager). The Alert Logic API does not offer any way to interact with events directly.

##Installation:
`pip install .`

It is advisable to us a virtualenv

##Simple usage:
`AlertLogic = AlPseudoAPI(username, password)
events = AlertLogic.get_events_from_incident(customer_id, incident_id, api_key)
results = AlertLogic.get_events(customer_id, events, summary=True)`


