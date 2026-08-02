WITH web_logs AS (
    SELECT event_id, source_ip, host_name, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'web' 
      AND source_ip IS NOT NULL
),
dns_logs AS (
    SELECT event_id, source_ip, host_name, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'dns' 
      AND source_ip IS NOT NULL
)
SELECT 
    w.event_id AS web_event_id,
    w.source_ip AS source_ip,
    d.event_id AS dns_event_id,
    d.host_name AS host_name,
    w.event_timestamp AS web_time,
    d.event_timestamp AS dns_time,
    w.raw_locator AS web_locator,
    d.raw_locator AS dns_locator
FROM web_logs w
JOIN dns_logs d
    ON w.source_ip = d.source_ip
WHERE d.event_timestamp >= w.event_timestamp - INTERVAL '2 minutes'
  AND d.event_timestamp <= w.event_timestamp + INTERVAL '5 minutes'
LIMIT 100;