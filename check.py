#!/usr/bin/python

import json
import requests
import subprocess
import pprint
import sys


def get_links(url):
    command = "phantomjs --ignore-ssl-errors=true /tmp/check.js " + url
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = proc.stdout.read().split("\n")
    return filter(None, result)


def get_link_results(links, api_key):
    threat_entries = []
    for link in links:
        threat_entries.append({"url": link})
    data = {
        "client": {
            "clientId": "securitysquadwebifier",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }
    headers = {"Content-type": "application/json"}
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    response = requests.post(url, json=data, headers=headers)
    return json.loads(response.content)


def format_result(response, url, links_length):
    if not response.get("matches", []):
        return {
            "result": "CLEAN",
            "info": {
                "matches": []
            }
        }

    matches = (match['threat']['url'] for match in response['matches'])
    if url in matches or len(matches)/links_length > 0.4:
        result = "MALICIOUS"
    else:
        result = "SUSPICIOUS"

    return {
        "result": result,
        "info": {
            "matches": matches
        }
    }


if __name__ == "__main__":
    if len(sys.argv) == 4:
        prefix = sys.argv[1]
        url = sys.argv[2]
        api_key = sys.argv[3]
        links = get_links(url)
        print links
        response = get_link_results(links, api_key)
        print response
        if response.get("error", False):
            print response.get("error")
        else:
            result = format_result(response, url, len(links))
            print '{}: {}'.format(prefix, json.dumps(result))
    else:
        print "prefix, url or api_key missing"
