# AlertLogic-event-api

Client side API for interacting with Alert Logic incidents and events (from threat manager). Alert Logic does not offer an API or any way to interact with events directly. This API also provides additional contextual summary information of all of the events tied to the specific incident.

##Requirements
The only requirement is requests

It is advisable to install within a virtualenv

##Simple usage:
```python
from alapi import alapi

incident = alapi.Incident(incident_id, customer_id, api_key, username, password)
print incident
```
Example output (with dummy data) included - [sample_output](https://github.com/brokensound77/AlertLogic-event-api/blob/master/sample_output.md)

for full API documentation, refer to the [wiki](https://github.com/brokensound77/AlertLogic-event-api/wiki/API-Documentation)
