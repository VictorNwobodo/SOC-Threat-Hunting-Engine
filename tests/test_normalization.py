import json
from pathlib import Path
import pytest

FIXTURE_PATH = Path("tests/fixtures/schema-fixtures.json")

def load_fixtures():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["fixtures"]

def normalize_record(source: str, raw_data: str | dict):
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except Exception:
            return "quarantine", "invalid_json"

    record = raw_data.get("record", {}) if isinstance(raw_data.get("record"), dict) else {}
    timestamp = (
        raw_data.get("timestamp") or 
        raw_data.get("event_time") or 
        raw_data.get("time") or 
        record.get("timestamp")
    )
    if not timestamp:
        return "quarantine", "missing_time"

    identity = (
        raw_data.get("username") or 
        raw_data.get("identity") or 
        record.get("username")
    )

    action = (
        raw_data.get("action") or 
        raw_data.get("result") or 
        raw_data.get("event") or 
        raw_data.get("event_name") or 
        record.get("action") or 
        record.get("event")
    )

    if not action:
        if source == "web":
            action = "web_request"
        elif source == "dns":
            action = "dns_query"
        elif source == "firewall":
            action = "network_deny"

    return "accepted", {
        "time": timestamp,
        "identity": identity,
        "event_type": action
    }

def canonicalize_identity(identity: str) -> str:
    if "@" in identity:
        identity = identity.split("@")[0]
    if "\\" in identity:
        identity = identity.split("\\")[-1]
    return identity


# --- Pytest Test Functions ---

def test_auth_fixtures():
    # Uses .get("source") to safely skip fixture items without a "source" key
    fixtures = [f for f in load_fixtures() if f.get("source") == "auth" and "input" in f]
    for fix in fixtures:
        status, result = normalize_record(fix["source"], fix["input"])
        if fix["id"].startswith("AUTH-"):
            assert status == "accepted"
            assert result["time"] == fix["expected"]["time"]
            assert result["identity"] == fix["expected"]["identity"]
            assert result["event_type"] == fix["expected"]["event_type"]

def test_quarantine_fixtures():
    fixtures = [f for f in load_fixtures() if "quarantine_reason" in f.get("expected", {})]
    for fix in fixtures:
        status, reason = normalize_record(fix["source"], fix["input"])
        assert status == "quarantine"
        assert reason == fix["expected"]["quarantine_reason"]

def test_identity_alias():
    alias_fix = next(f for f in load_fixtures() if f["id"] == "IDENTITY-ALIAS")
    for alias in alias_fix["aliases"]:
        assert canonicalize_identity(alias) == alias_fix["expected"]["canonical_identity"]