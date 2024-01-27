#!/usr/bin/env python

from OTXv2 import OTXv2
import argparse
import get_malicious
import hashlib
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json

# Get the parent directory of the script
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# Set the socket address for sending events
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

# Function to send an event to Wazuh
def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = '1:dns_stats:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->dns_stats:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    
    # Connect to the Wazuh socket and send the event
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Set API key and OTX server
API_KEY = 'APIKEY HERE'
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

# Read the Wazuh alert file
alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()

# Extract the queried hostname from the Sysmon Event
dns_query_name = alert["data"]["win"]["eventdata"]["queryName"]

# Get malicious indicators related to the hostname
alerts = get_malicious.hostname(otx, dns_query_name)

# Check if there are any alerts
if len(alerts) > 0:
    print('Identified as potentially malicious')
    # Prepare the alert output for Wazuh
    alert_output = {}
    alert_output["dnsstat"] = {}
    alert_output["integration"] = "dnsstat"
    alert_output["dnsstat"]["query"] = dns_query_name
    # Send the event to Wazuh
    send_event(alert_output, alert["agent"])
else:
    print('Unknown or not identified as malicious')
