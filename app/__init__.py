from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Exact least-privilege permissions
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    permissions = workflow.get("permissions", {})

    if permissions != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger safety
    event = payload.get("event")

    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests / matrix / failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner != "actions":
            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Multi-stage image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Non-root runtime
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret handling
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. Critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Image digest
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production requirements
    if payload.get("target") == "production":
        if (
            event != "push"
            or payload.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }