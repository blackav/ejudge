#! /bin/python3

import requests
import os
import urllib.parse
import sys

HOST = 'https://HOST.COM'
TOKEN = 'USER_TOKEN'

def ejudge_submit_run_input(contest_id, prob_id, lang_id, prog_file, input_file):
    with open(prog_file, "r") as f:
        prog_txt = f.read()
    with open(input_file, "r") as f:
        input_txt = f.read()
    headers = {
        "Authorization": "Bearer AQAA" + TOKEN
    }
    data = {
        "contest_id": contest_id,
        "prob_id": prob_id,
        "lang_id": lang_id,
        "text_form_input": input_txt,
        "text_form" : prog_txt,
    }
    url = HOST + "/ej/api/v1/master/submit-run-input"
    response = requests.post(url, data = data, headers = headers)
    if response.status_code != 200:
        return
    rj = response.json()
    if not rj["ok"]:
        return
    print(rj)
    submit_id = rj["result"]["submit_id"]
    print(submit_id)

ejudge_submit_run_input(1, "A", "gcc", "a_gcc_1.c", "input.txt")
