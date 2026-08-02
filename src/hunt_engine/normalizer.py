import json
import hashlib
from datetime import datetime, timezone

def canonicalize_identity(identity: str | None) -> str | None:
    """Canonicalizes identity by stripping domain prefixes and email suffixes."""
    if not identity:
        return None
    if "@" in identity:
        identity = identity.split("@")[0]
    if "\\" in identity:
        identity = identity.split("\\")[-1]
    return identity.strip()

def compute_content_hash(source_type: str, raw_str: str) -> str:
    """Computes SHA-256 hash of raw record for deduplication."""
    return hashlib.sha256(f"{source_type}:{raw_str}".encode('utf-8')).hexdigest()

def normalize_event(source_type: str, line_number: int, raw_line: str, clock_offsets: dict = None):
    """
    Parses a raw line from a source file and normalizes it.
    Returns tuple: (status, record_dict_or_quarantine_dict)
    """
    clock_offsets = clock_offsets or {}
    
    # 1. Check JSON validity
    try:
        data = json.loads(raw_line)
    except Exception:
        return "quarantine", {
            "source_file": f"{source_type}.jsonl",
            "line_number": line_number,
            "quarantine_reason": "invalid_json",
            "raw_payload": raw_line[:500]
        }

    if not isinstance(data, dict):
        return "quarantine", {
            "source_file": f"{source_type}.jsonl",
            "line_number": line_number,
            "quarantine_reason": "invalid_json",
            "raw_payload": raw_line[:500]
        }

    # 2. Extract nested record if schema v3
    record = data.get("record", {}) if isinstance(data.get("record"), dict) else {}
    schema_version = str(data.get("schema_version", "1"))

    # 3. Extract time anchor across v1, v2, v3
    raw_time = (
        data.get("timestamp") or 
        data.get("event_time") or 
        data.get("time") or 
        record.get("timestamp")
    )
    if not raw_time:
        return "quarantine", {
            "source_file": f"{source_type}.jsonl",
            "line_number": line_number,
            "quarantine_reason": "missing_time",
            "raw_payload": raw_line[:500]
        }

    # Apply clock skew correction if source has known offset
    offset = clock_offsets.get(source_type, 0)
    
    # 4. Extract Identity
    identity = canonicalize_identity(
        data.get("username") or 
        data.get("identity") or 
        record.get("username") or
        data.get("user")
    )

    # 5. Extract Event Type / Action
    event_type = (
        data.get("action") or 
        data.get("result") or 
        data.get("event") or 
        data.get("event_name") or 
        record.get("action") or 
        record.get("event")
    )

    if not event_type:
        if source_type == "web":
            event_type = "web_request"
        elif source_type == "dns":
            event_type = "dns_query"
        elif source_type == "firewall":
            event_type = "network_deny"
        elif source_type == "endpoint":
            event_type = "process_start"
        else:
            event_type = "unknown_action"

    # Extract additional context fields
    source_ip = data.get("src_ip") or data.get("source_ip") or record.get("src_ip")
    dest_ip = data.get("dest_ip") or data.get("destination_ip") or record.get("dest_ip")
    host_name = data.get("host") or data.get("hostname") or data.get("computer_name") or record.get("host")
    event_id = data.get("id") or data.get("event_id") or f"{source_type}-{line_number}"

    content_hash = compute_content_hash(source_type, raw_line.strip())

    normalized_record = {
        "event_id": str(event_id),
        "source_type": source_type,
        "event_timestamp": raw_time,
        "clock_skew_seconds": offset,
        "actor_user": identity,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "host_name": host_name,
        "event_action": event_type,
        "raw_locator": f"{source_type}.jsonl:{line_number}",
        "schema_version": schema_version,
        "content_hash": content_hash
    }

    return "accepted", normalized_record