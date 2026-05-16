import json
import os
import time
import base64
import urllib.request
import urllib.error
import urllib.parse
import subprocess
import tempfile
import re
from datetime import datetime, timezone
from pathlib import Path

DB_FILE = Path(__file__).parent / "data" / "queue.json"

def read_db():
    try:
        if DB_FILE.exists():
            return json.loads(DB_FILE.read_text())
    except Exception:
        pass
    return {"urls": [], "pointer": 0, "dailyCount": 0, "lastBatchDate": None, "log": []}

def write_db(db):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    DB_FILE.write_text(json.dumps(db, indent=2))

def add_log(db, msg, kind="info"):
    print(f"[{datetime.now().isoformat()}] {msg}")
    db["log"].insert(0, {"ts": int(time.time()*1000), "msg": msg, "type": kind})
    if len(db["log"]) > 500:
        db["log"] = db["log"][:500]

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_jwt(sa):
    now = int(time.time())
    header  = b64url(json.dumps({"alg":"RS256","typ":"JWT"}))
    payload = b64url(json.dumps({"iss":sa["client_email"],"scope":"https://www.googleapis.com/auth/indexing","aud":"https://oauth2.googleapis.com/token","exp":now+3600,"iat":now}))
    signing_input = f"{header}.{payload}"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
        f.write(sa["private_key"])
        key_file = f.name
    result = subprocess.run(["openssl","dgst","-sha256","-sign",key_file],input=signing_input.encode(),capture_output=True)
    os.unlink(key_file)
    if result.returncode != 0:
        raise Exception(f"Sign failed: {result.stderr.decode()}")
    sig = base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode()
    return f"{signing_input}.{sig}"

def get_access_token(sa):
    jwt  = make_jwt(sa)
    body = urllib.parse.urlencode({"grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer","assertion":jwt}).encode()
    req  = urllib.request.Request("https://oauth2.googleapis.com/token",data=body,headers={"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    with urllib.request.urlopen(req) as res:
        data = json.loads(res.read())
    if "access_token" not in data:
        raise Exception(data.get("error_description","Token failed"))
    return data["access_token"]

def index_url(url, token):
    body = json.dumps({"url":url,"type":"URL_UPDATED"}).encode()
    req  = urllib.request.Request("https://indexing.googleapis.com/v3/urlNotifications:publish",data=body,headers={"Content-Type":"application/json","Authorization":f"Bearer {token}"},method="POST")
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        raise Exception(err.get("error",{}).get("message",f"HTTP {e.code}"))

def main():
    print("Google Indexing Bot starting")
    sa_raw = os.environ.get("GOOGLE_SERVICE_ACCOUNT")
    if not sa_raw:
        print("ERROR: GOOGLE_SERVICE_ACCOUNT secret not set!")
        exit(1)
    sa  = json.loads(sa_raw)
    db  = read_db()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if db.get("lastBatchDate") != today:
        db["dailyCount"] = 0
        db["lastBatchDate"] = today
    if db["dailyCount"] >= 10:
        add_log(db, "Daily limit reached. Skipping.", "warn")
        write_db(db); return
    pending = [u for u in db["urls"] if u["status"]=="pending"]
    if not pending:
        add_log(db, "No pending URLs.", "warn")
        write_db(db); return
    budget = 10 - db["dailyCount"]
    add_log(db, f"Firing {budget} URLs from pointer #{db['pointer']}")
    token = get_access_token(sa)
    sent = 0
    ptr  = db["pointer"]
    while sent < budget and ptr < len(db["urls"]):
        while ptr < len(db["urls"]) and db["urls"][ptr]["status"] != "pending":
            ptr += 1
        if ptr >= len(db["urls"]): break
        item = db["urls"][ptr]
        try:
            index_url(item["url"], token)
            item["status"] = "success"
            item["sentAt"] = int(time.time()*1000)
            add_log(db, f"Indexed: {item['url']}", "success")
            sent += 1
            db["dailyCount"] += 1
        except Exception as e:
            item["status"] = "error"
            item["error"]  = str(e)
            add_log(db, f"Failed: {item['url']} - {e}", "error")
        ptr += 1
        db["pointer"] = ptr
        write_db(db)
    add_log(db, f"Done - {sent} sent today ({db['dailyCount']}/10)", "success")
    write_db(db)

if __name__ == "__main__":
    main()
