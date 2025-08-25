# ❌ Código intencionalmente vulnerable para pruebas de SAST
from fastapi import FastAPI, Query, Body
import sqlite3
import os, subprocess, hashlib, pickle, requests

app = FastAPI()

# 🔑 1) Credencial/secreto hardcodeado (Hardcoded secret)
SECRET_KEY = "supersecret123"  # Noncompliant: hardcoded secret in code

# DB inicial para el ejemplo
def get_conn():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
    conn.commit()
    return conn

# 🧨 2) SQL Injection por concatenación
@app.get("/user")
def get_user(username: str = Query(..., description="Try: admin' OR '1'='1")):
    conn = get_conn()
    c = conn.cursor()
    # Noncompliant: concatenación directa del parámetro en la consulta
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    c.execute(query)  # Sonar: SQL injection (use parameterized queries)
    rows = c.fetchall()
    return {"rows": rows, "query": query}

# 📂 3) Path Traversal (leer archivo arbitrario)
@app.get("/read")
def read_file(path: str = Query(..., description="Try: ../../etc/hosts")):
    # Noncompliant: abrir rutas controladas por el usuario sin validación
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {"head": f.read(200)}

# 💥 4) Command Injection (shell=True)
@app.get("/exec")
def exec_ping(host: str = Query(..., description="Try: 127.0.0.1; ls")):
    # Noncompliant: concatena entrada a un comando del sistema
    cmd = "ping -c 1 " + host
    out = subprocess.check_output(cmd, shell=True)  # Sonar: Command injection
    return {"cmd": cmd, "out": out.decode(errors="ignore")[:120]}

# 📦 5) Deserialización insegura (pickle)
@app.post("/pickle")
def load_pickle(payload: bytes = Body(...)):
    # Noncompliant: deserialización de datos no confiables
    obj = pickle.loads(payload)  # Sonar: Insecure deserialization
    return {"type": str(type(obj))}

# 🔐 6) Criptografía débil (MD5)
@app.get("/hash")
def weak_hash(password: str = Query(...)):
    # Noncompliant: MD5 inseguro
    digest = hashlib.md5(password.encode()).hexdigest()
    return {"md5": digest}

# 🌐 7) TLS verificación deshabilitada
@app.get("/fetch")
def insecure_fetch(url: str = Query(..., description="Try: https://example.com")):
    # Noncompliant: verify=False deshabilita la verificación de certificados
    r = requests.get(url, verify=False)  # Sonar: Disabling certificate validation
    return {"status": r.status_code, "len": len(r.text)}

# 🎯 8) CORS abierto (si lo añadieras con fastapi.middleware.cors, allow_origins=['*'])
#     Sonar lo suele marcar como hotspot de seguridad (revisar configuración).
