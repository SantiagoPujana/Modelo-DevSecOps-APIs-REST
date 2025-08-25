from fastapi.testclient import TestClient
import main

client = TestClient(main.app)

def test_smoke():
    r = client.get("/hash", params={"password": "x"})
    assert r.status_code == 200