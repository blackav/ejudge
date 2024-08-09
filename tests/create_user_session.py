#! /bin/python3

import requests
import os
import uuid
import urllib.parse
import sys
import json
import dotenv
import unittest

MASTER_API_PREFIX = '/ej/api/v1/master/'
MASTER_CLIENT_PREFIX = '/ej/api/v1/client/'
HEADERS = {}

# contest_id
# other_user_id
# other_user_login
# sender_ip
# sender_ssl_flag
# duration
# locale_id
# create_reg
# base_contest_id

def ejudge_create_user_session(contest_id, other_user_id = None, other_user_login = None,
        sender_ip = None, sender_ssl_flag = None, duration = None, locale_id = None,
        create_reg = None, base_contest_id = None):
    url = URL + MASTER_API_PREFIX + "create-user-session"
    data = {
        "contest_id" : contest_id,
    }
    if other_user_id is not None: data["other_user_id"] = other_user_id
    if other_user_login is not None: data["other_user_login"] = other_user_login
    if sender_ip is not None: data["sender_ip"] = sender_ip
    if sender_ssl_flag is not None: data["sender_ssl_flag"] = sender_ssl_flag
    if duration is not None: data["duration"] = duration
    if locale_id is not None: data["locale_id"] = locale_id
    if create_reg is not None: data["create_reg"] = create_reg
    if base_contest_id is not None: data["base_contest_id"] = base_contest_id
    return requests.post(url, data = data, headers = HEADERS)
 
# other_user_id | other_user_login
# contest_id
# op: delete | insert | upsert | update
# status: ok | pending | rejected
# is_invisible
# is_banned
# is_locked
# is_incomplete
# is_disqualified
# is_privileged
# is_reg_readonly
# ignore
# clear_name
# name

def ejudge_change_registration(contest_id,
        op,
        other_user_id = None,
        other_user_login = None,
        status = None,
        is_invisible = None,
        is_banned = None,
        is_locked = None,
        is_incomplete = None,
        is_disqualified = None,
        is_privileged = None,
        is_reg_readonly = None,
        ignore = None,
        clear_name = None,
        name = None):
    url = URL + MASTER_API_PREFIX + "change-registration"
    data = {
        "contest_id" : contest_id,
        "op": op,
    }
    if other_user_id is not None: data["other_user_id"] = other_user_id
    if other_user_login is not None: data["other_user_login"] = other_user_login
    if status is not None: data["status"] = status
    if is_invisible is not None: data["is_invisible"] = is_invisible
    if is_banned is not None: data["is_banned"] = is_banned
    if is_locked is not None: data["is_locked"] = is_locked
    if is_incomplete is not None: data["is_incomplete"] = is_incomplete
    if is_disqualified is not None: data["is_disqualified"] = is_disqualified
    if is_privileged is not None: data["is_privileged"] = is_privileged
    if is_reg_readonly is not None: data["is_reg_readonly"] = is_reg_readonly
    if ignore is not None: data["ignore"] = ignore
    if clear_name is not None: data["clear_name"] = clear_name
    if name is not None: data["name"] = name
    return requests.post(url, data = data, headers = HEADERS)

def ejudge_unpriv_contest_status(contest_id, cookie=None, client_key=None):
    url = URL + MASTER_CLIENT_PREFIX + "contest-status-json"
    headers = {}
    cookies = {}
    data = {
        "contest_id" : contest_id,
    }
    if cookie is not None: data["SID"] = cookie
    if client_key is not None: cookies["EJSID"] = client_key
    return requests.get(url + '?' + urllib.parse.urlencode(data), headers = headers, cookies = cookies)

class TestCreateSession(unittest.TestCase):
    def test_000(self):
        print("Delete user:")
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        print("Status: ", r.status_code)
        print("Reply: ", json.dumps(r.json(), indent=4))
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])

        print("Create user:")
        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", name="Test user")
        print("Status: ", r.status_code)
        print("Reply: ", json.dumps(r.json(), indent=4))
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])

        print("Create session:")
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

        print("Checking session:")
        r = ejudge_unpriv_contest_status(CONTEST_ID, cookie=j["result"]["cookie"], client_key=j["result"]["client_key"])
        print("Status: ", r.status_code)
        print("Reply: ", json.dumps(r.json(), indent=4))
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

    def test_001(self):
        print("Delete user:")
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

        # must fail, this user is not registered
        print("Create session:")
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_USER_NOT_REGISTERED")
    
    def test_002(self):
        # must fail, this user does not exist
        r = ejudge_create_user_session(CONTEST_ID, other_user_login="ueuesbx92923dhshsdsa")
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 404)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_INV_USER_ID")
    
    def test_003(self):
        # must fail, this contest does not exist
        r = ejudge_create_user_session(888983, other_user_login=OTHER_LOGIN)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        ### TO BE FIXED
        self.assertEqual(r.status_code, 200)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_PERMISSION_DENIED")

    def test_004(self):
        # must fail, this user does not exist
        r = ejudge_create_user_session(CONTEST_ID, other_user_id=448393)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 404)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_INV_USER_ID")

    def test_005(self):
        # auto create registration
        print("Delete user:")
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        print("Create session:")
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, create_reg=True)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

    # reject not-ok users
    def test_006(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="pending", name="Test user")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])

        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_USER_NOT_REGISTERED")

    # reject disqualified users
    def test_007(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])

        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", is_disqualified=True, name="Test user")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])

        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_DISQUALIFIED")

#    # reject incomplete users
#    def test_010(self):
#        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
#        j = r.json()
#        self.assertEqual(r.status_code, 200)
#        self.assertTrue(j["ok"])
#
#        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", is_incomplete=True, name="Test user")
#        self.assertEqual(r.status_code, 200)
#        j = r.json()
#        self.assertTrue(j["ok"])
#
#        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN)
#        print("Status: ", r.status_code)
#        j = r.json()
#        print("Reply: ", json.dumps(j, indent=4))
#        self.assertEqual(r.status_code, 400)
#        self.assertFalse(j["ok"])
#        self.assertEqual(j["error"]["symbol"],"ERR_DISQUALIFIED")

    # test registration from base contest_id, user not registered
    def test_011(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(BASE_CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, create_reg=True, base_contest_id=BASE_CONTEST_ID)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_USER_NOT_REGISTERED")

    # test registration from base contest_id, user not ok
    def test_012(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(BASE_CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        print("Create user:")
        r = ejudge_change_registration(BASE_CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="pending", name="1111")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, create_reg=True, base_contest_id=BASE_CONTEST_ID)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_USER_NOT_REGISTERED")

    def test_013(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(BASE_CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        print("Create user:")
        r = ejudge_change_registration(BASE_CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", is_locked=True, name="1111")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, create_reg=True, base_contest_id=BASE_CONTEST_ID)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"]["symbol"],"ERR_USER_LOCKED")

    def test_014(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(BASE_CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        j = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        print("Create user:")
        r = ejudge_change_registration(BASE_CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", is_invisible=True, name="12345")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, create_reg=True, base_contest_id=BASE_CONTEST_ID)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))

    def test_015(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", name="Test user")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, locale_id=1)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["result"]["locale_id"], 1)

    def test_016(self):
        r = ejudge_change_registration(CONTEST_ID, "delete", other_user_login=OTHER_LOGIN, ignore=True)
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        r = ejudge_change_registration(CONTEST_ID, "insert", other_user_login=OTHER_LOGIN, status="ok", name="Test user")
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertTrue(j["ok"])
        duration=1000
        r = ejudge_create_user_session(CONTEST_ID, other_user_login=OTHER_LOGIN, duration=duration)
        print("Status: ", r.status_code)
        j = r.json()
        print("Reply: ", json.dumps(j, indent=4))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(j["ok"])
        server_time = j["server_time"]
        expiration_time = j["result"]["expire"]
        self.assertTrue(expiration_time > server_time + duration - 5 and expiration_time < server_time + duration + 5)


if __name__ == "__main__":
    dotenv.load_dotenv()
    global URL
    URL = os.getenv("EJUDGE_URL")
    global TOKEN
    TOKEN = os.getenv("EJUDGE_TOKEN")
    HEADERS["Authorization"] = "Bearer AQAA" + TOKEN
    global CONTEST_ID
    CONTEST_ID = os.getenv("EJUDGE_CONTEST_ID")
    global OTHER_LOGIN
    OTHER_LOGIN = os.getenv("EJUDGE_OTHER_LOGIN")
    global BASE_CONTEST_ID
    BASE_CONTEST_ID = os.getenv("EJUDGE_BASE_CONTEST_ID")

    unittest.main()
