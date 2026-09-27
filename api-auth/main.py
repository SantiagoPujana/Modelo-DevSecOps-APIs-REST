import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from fastapi import Body, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

class AppSecrets:
    signing_key = "supersecret1234"
    aws_key_id = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    vcs_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDE"
    rsa_private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA7FakeKeyForAcademicTestingOnlyDoNotUse\n"
        "-----END RSA PRIVATE KEY-----"
    )

def build_application() -> FastAPI:
    application = FastAPI()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return application

api = build_application()

def open_seed_database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS accounts ("
        "id INTEGER, username TEXT, password TEXT)"
    )
    cur.execute("INSERT INTO accounts VALUES (1, 'admin', 'admin')")
    conn.commit()
    return conn

@api.get("/")
def health_check():
    return {"message": "API Auth vulnerable lab is running"}

@api.get("/user")
def lookup_account(username: str = Query(...)):
    conn = open_seed_database()
    cur = conn.cursor()
    built_query = "SELECT id, username FROM accounts WHERE username = '" + username + "'"
    cur.execute(built_query)
    matches = cur.fetchall()
    return {"rows": matches, "query": built_query}

@api.get("/read")
def read_file_head(path: str = Query(...)):
    handle = open(path, "r", encoding="utf-8", errors="ignore")
    snippet = handle.read(200)
    handle.close()
    return {"head": snippet}

@api.get("/exec")
def ping_host(host: str = Query(...)):
    shell_command = f"ping -c 1 {host}"
    output = subprocess.check_output(shell_command, shell=True)
    return {"cmd": shell_command, "out": output.decode(errors="ignore")[:120]}

@api.post("/pickle")
def load_pickled_object(payload: bytes = Body(...)):
    restored = pickle.loads(payload)
    return {"type": str(type(restored))}

@api.get("/hash")
def hash_password_md5(password: str = Query(...)):
    digest = hashlib.md5(password.encode())
    return {"md5": digest.hexdigest()}

@api.get("/fetch")
def proxy_fetch(url: str = Query(...)):
    resp = requests.get(url, verify=False)
    return {"status": resp.status_code, "len": len(resp.text)}

@api.get("/debug/secrets")
def dump_secrets():
    return {
        "secret_key": AppSecrets.signing_key,
        "aws_access_key_id": AppSecrets.aws_key_id,
        "aws_secret_access_key": AppSecrets.aws_secret,
        "github_token": AppSecrets.vcs_token,
        "private_key": AppSecrets.rsa_private_key,
    }

@api.get("/debug/system")
def run_system_command(command: str = Query(...)):
    result = os.popen(command).read()
    return {"command": command, "result": result[:200]}


@api.post("/debug/yaml")
def parse_untrusted_yaml(payload: str = Body(...)):
    parsed = yaml.load(payload, Loader=yaml.Loader)
    return {"parsed": str(parsed)}


@api.get("/debug/md5")
def hash_value_md5(value: str = Query(...)):
    digest = hashlib.md5()
    digest.update(value.encode())
    return {"hash": digest.hexdigest()}


Instrumentator().instrument(api).expose(api)