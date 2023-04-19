import requests
import json
import datetime
import hashlib
import hmac
import base64
import os
from datetime import date
from datetime import timedelta

# temp vars
today = date.today()
yesterday = today - timedelta(days=1)

# Set up authentication credentials
api_key = 'YOUR_API_KEY'
auth_token = 'YOUR_AUTH_TOKEN'
# Update the customer ID to your Log Analytics workspace ID
customer_id = os.environ['WorkspaceID']

# For the shared key, use either the primary or the secondary Connected Sources client authentication key
shared_key = os.environ['WorkspaceKey']

# The log type is the name of the event that is being submitted
log_type = 'sendgridtest'
json_data = []

SUBUSERS_URL = 'https://api.sendgrid.com/v3/subusers'
API_KEYS_URL = 'https://api.sendgrid.com/v3/api_keys'
MESSAGES_URL = 'https://api.sendgrid.com/v3/messages'

headers = {'Authorization': f'Bearer {auth_token}'}

#####################
######Functions######
#####################

# Build the API signature


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

# Build and send a request to the POST API


def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + \
        resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))


# Get list of subusers
response = requests.get(SUBUSERS_URL, headers=headers)
response.raise_for_status()
subusers = response.json()

# Loop through subusers and get API key for each one
for subuser in subusers:
    subuser_headers = {
        'Authorization': f'Bearer {auth_token}',
        'on-behalf-of': f'{subuser["username"]}'
    }
    subuser_id = subuser['id']

    # Get list of API keys for the subuser
    response = requests.get(API_KEYS_URL, headers=subuser_headers)
    if response.status_code != 200:
        print(
            f'Failed to get API keys for subuser {subuser_id}: {response.status_code} {response.reason}')
        continue

    api_keys = response.json()['result']

    # Loop through API keys and get messages for each one
    for api_key in api_keys:
        query = f"?limit=100000&query=((last_event_time BETWEEN TIMESTAMP '{yesterday}T00%3A00%3A00.000Z' AND TIMESTAMP '{today}T00%3A00%3A00.000Z') AND api_key_id='{api_key['api_key_id']}')"

        message_response = requests.get(
            MESSAGES_URL+query, headers=headers)
        if message_response.status_code != 200:
            print(
                f'Failed to get messages for API key {api_key["api_key_id"]}: {message_response.status_code} {message_response.reason}')
            continue

        messages = message_response.json()['messages']

        # Loop through messages and print them
        if messages:
            for message in messages:
                message['subuser'] = subuser['username']
                message['api_key_name'] = api_key['name']
                json_data.append(message)
                print("Inserted data into json_data")


body = json.dumps(json_data)
post_data(customer_id, shared_key, body, log_type)
