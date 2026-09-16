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
from pydantic import BaseModel

app = FastAPI(
    title="Vulnerable API Lab - Educational Environment",
    description="API diseñada exclusivamente para pruebas de seguridad y laboratorios de hacking ético.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRETS_STORE = {
    "SECRET_KEY": "supersecret1234",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDE",
    "PRIVATE_KEY": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7FakeKeyForAcademicTestingOnlyDoNotUse
-----END RSA PRIVATE KEY-----"""
}

def get_db_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)"
    )
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
    connection.commit()
    return connection

class YamlPayload(BaseModel):
    payload: str

@app.get("/")
def read_root():
    return {"message": "API Auth vulnerable lab is running"}


@app.get("/user")
def find_user_by_username(username: str = Query(...)):
    """Vulnerabilidad: SQL Injection (Inyección por concatenación)"""
    connection = get_db_connection()
    cursor = connection.cursor()
    
    # Concatenación directa de cadenas
    sql_statement = f"SELECT id, username FROM users WHERE username = '{username}'"
    cursor.execute(sql_statement)
    user_rows = cursor.fetchall()
    connection.close()
    
    return {"rows": user_rows, "query": sql_statement}


@app.get("/read")
def fetch_file_content(path: str = Query(...)):
    """Vulnerabilidad: Path Traversal (Lectura arbitraria de archivos)"""
    with open(path, "r", encoding="utf-8", errors="ignore") as target_file:
        content = target_file.read(200)
    return {"head": content}


@app.get("/exec")
def execute_ping_command(host: str = Query(...)):
    """Vulnerabilidad: Command Injection (Ejecución vía subprocess)"""
    full_command = f"ping -c 1 {host}"
    process_output = subprocess.check_output(full_command, shell=True)
    return {"cmd": full_command, "out": process_output.decode(errors="ignore")[:120]}


@app.post("/pickle")
def process_pickle_payload(payload: bytes = Body(...)):
    """Vulnerabilidad: Insecure Deserialization (RCE vía Pickle)"""
    deserialized_object = pickle.loads(payload)
    return {"type": str(type(deserialized_object))}


@app.get("/hash")
def generate_md5_hash(password: str = Query(...)):
    """Vulnerabilidad: Weak Cryptography (MD5)"""
    hash_object = hashlib.md5(password.encode())
    return {"md5": hash_object.hexdigest()}


@app.get("/fetch")
def fetch_remote_url(url: str = Query(...)):
    """Vulnerabilidad: SSRF & Disabled SSL Verification"""
    response = requests.get(url, verify=False)
    return {"status": response.status_code, "len": len(response.text)}


@app.get("/debug/secrets")
def show_api_secrets():
    """Vulnerabilidad: Information Disclosure (Exposición de credenciales)"""
    return SECRETS_STORE


@app.get("/debug/system")
def execute_system_command(command: str = Query(...)):
    """Vulnerabilidad: Command Injection (Ejecución vía os.popen)"""
    command_output = os.popen(command).read()
    return {"command": command, "result": command_output[:200]}


@app.post("/debug/yaml")
def parse_yaml_payload(body: YamlPayload):
    """Vulnerabilidad: Insecure Deserialization (Unsafe YAML Loader)"""
    parsed_yaml = yaml.load(body.payload, Loader=yaml.Loader)
    return {"parsed": str(parsed_yaml)}


@app.get("/debug/md5")
def generate_debug_md5(value: str = Query(...)):
    """Vulnerabilidad: Weak Cryptography (MD5)"""
    digest = hashlib.md5(value.encode()).hexdigest()
    return {"hash": digest}


# Métricas
Instrumentator().instrument(app).expose(app)