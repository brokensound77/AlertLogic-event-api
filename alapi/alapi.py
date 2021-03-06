""" Alert Logic Event API """

# Author: Justin Ibarra (justin.s.ibarra@gmail.com)
# License: MIT - A full copy of the license is provided with this source code

from incidents import Incident, Event, threading
from errors import IncidentNotRetrievedError, EventNotRetrievedError


def get_event(event_id, customer_id, username, password, to_json=False):
    event = Event(event_id, customer_id)
    event.set_credentials(username, password)
    event.get_event()
    if to_json:
        return event.to_json()
    else:
        return event


def get_events(event_id_list, customer_id, username, password, suppress_errors=True, to_json=False):
    event_dict = {}
    threads = []
    errors = []

    def __multi_get_events(thread_event_id):  # for threading
        try:
            if to_json:
                event_dict[thread_event_id] = get_event(thread_event_id, customer_id, username, password).to_json()
            else:
                event_dict[thread_event_id] = get_event(thread_event_id, customer_id, username, password)
        except Exception as e:
            errors.append(e.message)
            pass

    for i in event_id_list:
        t = threading.Thread(target=__multi_get_events, args=(i,))
        threads.append(t)
        t.start()
    for _thread in threads:
        _thread.join()
    if not suppress_errors:
        raise EventNotRetrievedError('Their were errors retrieving some events: {0}'.format(errors))
    return event_dict


def get_incident(incident_id, customer_id, api_key, username, password, to_json=False):
    if to_json:
        return Incident(incident_id, customer_id, api_key, username, password).to_json()
    else:
        return Incident(incident_id, customer_id, api_key, username, password)


def get_incidents(incident_id_list, customer_id, api_key, username, password, suppress_errors=True, to_json=False):
    incident_dict = {}
    threads = []
    errors = []

    def __multi_get_incidents(thread_incident_id):  # for threading
        try:
            if to_json:
                incident_dict[thread_incident_id] = get_incident(
                    thread_incident_id, customer_id, api_key, username, password).to_json()
            else:
                incident_dict[thread_incident_id] = get_incident(
                    thread_incident_id, customer_id, api_key, username, password)
        except Exception as e:
            errors.append(e.message)
            pass

    for i in incident_id_list:
        t = threading.Thread(target=__multi_get_incidents, args=(i,))
        threads.append(t)
        t.start()
    for _thread in threads:
        _thread.join()
    if not suppress_errors:
        raise IncidentNotRetrievedError('Their were errors retrieving some incidents: {0}'.format(errors))
    return incident_dict
