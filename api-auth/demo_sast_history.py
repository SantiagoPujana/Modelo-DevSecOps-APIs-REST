import hashlib
import sqlite3
import subprocess


def vulnerable_sql_search(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()


def vulnerable_command(value: str):
    return subprocess.check_output("echo " + value, shell=True)


def weak_password_hash(password: str):
    return hashlib.md5(password.encode()).hexdigest()