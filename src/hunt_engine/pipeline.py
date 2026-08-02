import os
import csv
from pathlib import Path
import duckdb
from hunt_engine.normalizer import normalize_event

def run_ingestion(raw_dir: Path, work_dir: Path, evidence_dir: Path):
    """
    Streams all 5 raw source .jsonl files, normalizes rows, routes corrupt lines to quarantine,
    deduplicates identical records, and stores clean events in DuckDB using batch inserts.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    db_path = work_dir / "clean.db"
    if db_path.exists():
        db_path.unlink()

    conn = duckdb.connect(str(db_path))

    # Initialize DuckDB Schema
    conn.execute("""
        CREATE TABLE normalized_events (
            event_id VARCHAR,
            source_type VARCHAR,
            event_timestamp TIMESTAMP WITH TIME ZONE,
            clock_skew_seconds DOUBLE,
            actor_user VARCHAR,
            source_ip VARCHAR,
            destination_ip VARCHAR,
            host_name VARCHAR,
            event_action VARCHAR,
            raw_locator VARCHAR,
            schema_version VARCHAR,
            content_hash VARCHAR PRIMARY KEY
        );

        CREATE TABLE quarantine_events (
            quarantine_id VARCHAR PRIMARY KEY,
            source_file VARCHAR,
            line_number BIGINT,
            quarantine_reason VARCHAR,
            raw_payload VARCHAR
        );
    """)

    sources = ["auth", "web", "dns", "firewall", "endpoint"]
    seen_hashes = set()
    
    source_stats = {}
    quarantine_rows = []
    
    # ENDPOINT clock offset (-3900s)
    clock_offsets = {"endpoint": -3900}

    for source in sources:
        source_file = raw_dir / "source" / f"{source}.jsonl"
        if not source_file.exists():
            continue

        print(f"Ingesting {source}.jsonl...")

        accepted_count = 0
        duplicate_count = 0
        quarantine_count = 0

        accepted_batch = []
        quarantine_batch = []

        with open(source_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                raw_line = line.strip()
                if not raw_line:
                    continue

                status, payload = normalize_event(source, line_no, raw_line, clock_offsets)

                if status == "quarantine":
                    quarantine_count += 1
                    quarantine_id = f"Q-{source.upper()}-{line_no}"
                    quarantine_batch.append((
                        quarantine_id,
                        payload["source_file"],
                        payload["line_number"],
                        payload["quarantine_reason"],
                        payload["raw_payload"]
                    ))
                    quarantine_rows.append({
                        "quarantine_id": quarantine_id,
                        "source_file": payload["source_file"],
                        "line_number": payload["line_number"],
                        "quarantine_reason": payload["quarantine_reason"],
                        "raw_payload": payload["raw_payload"]
                    })
                elif status == "accepted":
                    c_hash = payload["content_hash"]
                    if c_hash in seen_hashes:
                        duplicate_count += 1
                    else:
                        seen_hashes.add(c_hash)
                        accepted_count += 1
                        accepted_batch.append((
                            payload["event_id"],
                            payload["source_type"],
                            payload["event_timestamp"],
                            payload["clock_skew_seconds"],
                            payload["actor_user"],
                            payload["source_ip"],
                            payload["destination_ip"],
                            payload["host_name"],
                            payload["event_action"],
                            payload["raw_locator"],
                            payload["schema_version"],
                            payload["content_hash"]
                        ))

                # Batch insert every 50,000 records
                if len(accepted_batch) >= 50000:
                    conn.executemany("INSERT INTO normalized_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", accepted_batch)
                    accepted_batch.clear()

                if len(quarantine_batch) >= 50000:
                    conn.executemany("INSERT INTO quarantine_events VALUES (?, ?, ?, ?, ?)", quarantine_batch)
                    quarantine_batch.clear()

        # Flush remaining items
        if accepted_batch:
            conn.executemany("INSERT INTO normalized_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", accepted_batch)
        if quarantine_batch:
            conn.executemany("INSERT INTO quarantine_events VALUES (?, ?, ?, ?, ?)", quarantine_batch)

        source_stats[source] = {
            "accepted": accepted_count,
            "duplicated": duplicate_count,
            "quarantined": quarantine_count,
            "total": accepted_count + duplicate_count + quarantine_count
        }

    # 1. Write Data Quality Register CSV
    dq_path = evidence_dir / "data-quality-register.csv"
    with open(dq_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "accepted_count", "duplicate_count", "quarantine_count", "total_count"])
        for src, counts in source_stats.items():
            writer.writerow([src, counts["accepted"], counts["duplicated"], counts["quarantined"], counts["total"]])

    # 2. Export Quarantine CSV
    q_csv_path = work_dir / "quarantine.csv"
    with open(q_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["quarantine_id", "source_file", "line_number", "quarantine_reason", "raw_payload"])
        writer.writeheader()
        writer.writerows(quarantine_rows)

    # 3. Export Normalized Timeline CSV
    timeline_path = work_dir / "normalized-timeline.csv"
    conn.execute(f"COPY (SELECT event_id, source_type, event_timestamp, actor_user, source_ip, destination_ip, host_name, event_action, raw_locator FROM normalized_events ORDER BY event_timestamp ASC) TO '{timeline_path}' (HEADER, DELIMITER ',')")

    conn.close()
    print("Ingestion complete. Database clean.db and outputs generated successfully.")