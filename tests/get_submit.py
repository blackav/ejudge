#! /bin/python3

import requests
import os
import uuid
import urllib.parse
import sys

HOST = 'https://host.com'
TOKEN = 'USER_TOKEN'
CONTEST_ID = 1

URL = HOST + '/ej/api/v1/master/get-submit'

headers = {
        "Authorization": "Bearer AQAA" + TOKEN
}

data = {
    "contest_id" : CONTEST_ID,
    "submit_id" : sys.argv[1],
}
 
response = requests.get(URL + '?' + urllib.parse.urlencode(data), headers = headers)
print(response.text)


