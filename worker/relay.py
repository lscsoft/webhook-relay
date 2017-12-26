import requests

def posthook(payload, destinations):
    for destination in destinations:
        res = requests.post(destination, json=payload)
