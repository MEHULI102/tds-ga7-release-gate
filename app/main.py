from fastapi import FastAPI
from typing import Any

app = FastAPI()


EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

VIOLATIONS = [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
]


def check_permissions(workflow: dict[str, Any]) -> bool:
    permissions = workflow.get("permissions", {})

    # Must contain exactly the three required permissions.
    return permissions == EXPECTED_PERMISSIONS


def check_actions(workflow: dict[str, Any]) -> bool:
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref")

        # Official actions/* may use a version tag.
        if owner == "actions":
            continue

        # Every third-party action must use a full
        # 40-character lowercase hexadecimal SHA.
        if not isinstance(ref, str):
            return False

        if len(ref) != 40:
            return False

        if any(ch not in "0123456789abcdef" for ch in ref):
            return False

    return True


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    workflow = payload.get("workflow") or {}
    image = payload.get("image") or {}

    # ---------------------------------------------------------
    # 1. Permissions
    # ---------------------------------------------------------
    if not check_permissions(workflow):
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. Pull request security
    # ---------------------------------------------------------
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. Test/matrix requirements
    # ---------------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. GitHub Action pinning
    # ---------------------------------------------------------
    if not check_actions(workflow):
        violations.append("MUTABLE_ACTION")

    # ---------------------------------------------------------
    # 5. Container image requirements
    # ---------------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 6. Production-only requirements
    # ---------------------------------------------------------
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # Final decision
    # ---------------------------------------------------------
    decision = "promote" if not violations else "block"

    return {
        "decision": decision,
        "violations": violations,
    }