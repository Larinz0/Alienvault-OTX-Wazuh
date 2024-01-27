# Alien Vault OTX integration with Wazuh [2024]

Make sure that wazuh have installed OTXv2 
```bash
/var/ossec/framework/python/bin/python3 -m pip install OTXv2
```

Create 3 files into /var/ossec/integrations
```bash
 cd /var/ossec/integrations/ && touch custom-alienvault custom-alienvault.py get_malicious.py
```
## Files to be included in var/ossec/integration

custom-alienvault
```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```
custom-alienvault.py
```python
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

```
get_malicious.py
```bash
https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/is_malicious/get_malicious.py
```
🚨Remember after you have created this three files to do🚨
```bash
chown root:wazuh custom-alienvault custom-alienvault.py get_malicious.py && chmod 750 custom-alienvault custom-alienvault.py get_malicious.py
```
## Strings to be included in var/ossec/etc/ossec.conf
```pyhton
<integration>
    <name>custom-alienvault</name>
    <group>sysmon_event_22</group>
    <alert_format>json</alert_format>
</integration>
```
## File to be included in /var/ossec/etc/rules
alienOTX.xml
```pyhton
<group name="alienvault_alert,">
 <rule id="100010" level="12">
    <field name="integration">alienvault</field>
    <description>AlienVault - OTX DOMAIN Found</description>
    <options>no_full_log</options>
  </rule>
</group>
```
## Now we can restart our Wazuh
```bash
systemctl restart wazuh-manager
```
🚨[INFO] The tool will only trigger if the domain is present in OTX ALIENVAULT🚨
![alt text](https://i.ibb.co/D9z8Ys1/Cattura.png)
