"""
Mock API Server for Integration Testing.

Provides mock endpoints for platform integrations (Okta, GitHub, etc.)
to enable offline integration testing.

Environment Variables:
    MOCK_DELAY_MS: Simulated response delay in milliseconds (default: 0)
    MOCK_FAIL_RATE: Percentage of requests to fail (0-100, default: 0)
"""

import json
import os
import random
import time
from pathlib import Path

from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# Configuration
MOCK_DELAY_MS = int(os.getenv("MOCK_DELAY_MS", "0"))
MOCK_FAIL_RATE = int(os.getenv("MOCK_FAIL_RATE", "0"))
RESPONSES_DIR = Path(os.getenv("RESPONSES_DIR", "/app/responses"))


def apply_delay():
    """Apply configured response delay."""
    if MOCK_DELAY_MS > 0:
        time.sleep(MOCK_DELAY_MS / 1000.0)


def should_fail():
    """Check if request should fail based on fail rate."""
    if MOCK_FAIL_RATE > 0:
        return random.randint(1, 100) <= MOCK_FAIL_RATE
    return False


def load_response(platform: str, endpoint: str) -> dict | list | None:
    """Load a recorded response for an endpoint."""
    # Normalize endpoint to filename
    filename = endpoint.strip("/").replace("/", "_") + ".json"
    response_path = RESPONSES_DIR / platform / filename

    if response_path.exists():
        with open(response_path) as f:
            return json.load(f)
    return None


# =============================================================================
# Health Check
# =============================================================================


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "mock-api"})


# =============================================================================
# Okta Mock Endpoints
# =============================================================================


@app.route("/okta/api/v1/users", methods=["GET"])
def okta_users():
    """Mock Okta Users API."""
    apply_delay()

    if should_fail():
        return jsonify({"error": "Internal Server Error"}), 500

    # Try to load recorded response
    response = load_response("okta", "api_v1_users")
    if response:
        return jsonify(response)

    # Default mock response
    return jsonify([
        {
            "id": "00u1234567890",
            "status": "ACTIVE",
            "created": "2024-01-01T00:00:00.000Z",
            "profile": {
                "firstName": "Test",
                "lastName": "User",
                "email": "test@example.com",
                "login": "test@example.com",
            },
        },
    ])


@app.route("/okta/api/v1/groups", methods=["GET"])
def okta_groups():
    """Mock Okta Groups API."""
    apply_delay()

    if should_fail():
        return jsonify({"error": "Internal Server Error"}), 500

    response = load_response("okta", "api_v1_groups")
    if response:
        return jsonify(response)

    return jsonify([
        {
            "id": "00g1234567890",
            "created": "2024-01-01T00:00:00.000Z",
            "profile": {"name": "Everyone", "description": "All users"},
        },
    ])


# =============================================================================
# GitHub Mock Endpoints
# =============================================================================


@app.route("/github/api/v3/repos/<owner>/<repo>", methods=["GET"])
def github_repo(owner: str, repo: str):
    """Mock GitHub Repository API."""
    apply_delay()

    if should_fail():
        return jsonify({"message": "Internal Server Error"}), 500

    return jsonify({
        "id": 123456789,
        "name": repo,
        "full_name": f"{owner}/{repo}",
        "private": True,
        "default_branch": "main",
        "permissions": {"admin": True, "push": True, "pull": True},
    })


@app.route("/github/api/v3/orgs/<org>/repos", methods=["GET"])
def github_org_repos(org: str):
    """Mock GitHub Organization Repositories API."""
    apply_delay()

    if should_fail():
        return jsonify({"message": "Internal Server Error"}), 500

    return jsonify([
        {
            "id": 123456789,
            "name": "test-repo",
            "full_name": f"{org}/test-repo",
            "private": True,
            "default_branch": "main",
        },
    ])


# =============================================================================
# Jira Mock Endpoints
# =============================================================================


@app.route("/jira/rest/api/3/project", methods=["GET"])
def jira_projects():
    """Mock Jira Projects API."""
    apply_delay()

    if should_fail():
        return jsonify({"errorMessages": ["Internal error"]}), 500

    return jsonify({
        "values": [
            {
                "id": "10000",
                "key": "TEST",
                "name": "Test Project",
                "projectTypeKey": "software",
            },
        ],
    })


# =============================================================================
# Slack Mock Endpoints
# =============================================================================


@app.route("/slack/api/users.list", methods=["GET", "POST"])
def slack_users():
    """Mock Slack Users List API."""
    apply_delay()

    if should_fail():
        return jsonify({"ok": False, "error": "internal_error"})

    return jsonify({
        "ok": True,
        "members": [
            {
                "id": "U1234567890",
                "name": "testuser",
                "real_name": "Test User",
                "is_admin": False,
                "is_owner": False,
                "has_2fa": True,
            },
        ],
    })


# =============================================================================
# Datadog Mock Endpoints
# =============================================================================


@app.route("/datadog/api/v1/monitors", methods=["GET"])
def datadog_monitors():
    """Mock Datadog Monitors API."""
    apply_delay()

    if should_fail():
        return jsonify({"errors": ["Internal error"]}), 500

    return jsonify([
        {
            "id": 12345,
            "name": "CPU Monitor",
            "type": "metric alert",
            "query": "avg(last_5m):avg:system.cpu.user{*} > 80",
            "overall_state": "OK",
        },
    ])


# =============================================================================
# Generic Mock Endpoint
# =============================================================================


@app.route("/<platform>/<path:endpoint>", methods=["GET", "POST", "PUT", "DELETE"])
def generic_endpoint(platform: str, endpoint: str):
    """
    Generic mock endpoint that serves recorded responses.

    If no recorded response exists, returns a 404.
    """
    apply_delay()

    if should_fail():
        return jsonify({"error": "Internal Server Error"}), 500

    response = load_response(platform, endpoint)
    if response:
        return jsonify(response)

    return jsonify({"error": f"No mock response for {platform}/{endpoint}"}), 404


# =============================================================================
# Error Simulation Endpoints
# =============================================================================


@app.route("/simulate/error/<int:status_code>")
def simulate_error(status_code: int):
    """Simulate an HTTP error response."""
    apply_delay()
    return jsonify({"error": f"Simulated {status_code} error"}), status_code


@app.route("/simulate/delay/<int:ms>")
def simulate_delay(ms: int):
    """Simulate a slow response."""
    time.sleep(ms / 1000.0)
    return jsonify({"delayed_ms": ms})


@app.route("/simulate/timeout")
def simulate_timeout():
    """Simulate a timeout (60 second delay)."""
    time.sleep(60)
    return jsonify({"timeout": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
