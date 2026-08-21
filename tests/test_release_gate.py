from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_safe_preview():
    payload = {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/test",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4"
                },
                {
                    "owner": "thirdparty",
                    "name": "example",
                    "ref": "0123456789abcdef0123456789abcdef01234567"
                }
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }

    response = client.post("/release-gate", json=payload)

    assert response.status_code == 200
    assert response.json() == {
        "decision": "promote",
        "violations": []
    }