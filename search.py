import re

def search_api_name(api_data, pattern):
    matched_apis = []
    pattern = re.compile(pattern, re.IGNORECASE)
    for api in api_data:
        if pattern.search(api['API']):
            matched_apis.append(api['API'])
    return matched_apis

def search_api_description(api_data, pattern, event_sources=None):
    matched_apis = []
    pattern = re.compile(pattern, re.IGNORECASE)

    if event_sources is None:
        event_sources = [None]

    for api in api_data:
        if (pattern.search(api['Description'])
                and (event_sources is None or api['EventSource'] in event_sources)):
            matched_apis.append(api['EventSource'] + ":" + api['EventName'])

    return matched_apis
