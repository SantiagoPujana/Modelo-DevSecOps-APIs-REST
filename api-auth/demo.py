import hashlib
import os
import pickle
import sqlite3
import subprocess


def demo_sql_injection(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()


def demo_command_injection(value: str):
    command = "echo " + value
    return subprocess.check_output(command, shell=True)


def demo_path_traversal(filename: str):
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()


def demo_unsafe_deserialization(data: bytes):
    return pickle.loads(data)


def demo_weak_hash(password: str):
    return hashlib.md5(password.encode()).hexdigest()