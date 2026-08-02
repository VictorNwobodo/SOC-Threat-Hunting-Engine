WITH edr_activity AS (
    SELECT event_id, actor_user, host_name, source_ip, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'endpoint' 
      AND host_name IS NOT NULL
),
fw_denies AS (
    SELECT event_id, host_name, source_ip, destination_ip, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'firewall' 
      AND event_action = 'network_deny' 
      AND host_name IS NOT NULL
)
SELECT 
    e.event_id AS edr_event_id,
    e.actor_user AS actor,
    e.host_name AS host_name,
    f.event_id AS fw_event_id,
    f.source_ip AS source_ip,
    f.destination_ip AS dest_ip,
    e.event_timestamp AS edr_time,
    f.event_timestamp AS fw_time,
    e.raw_locator AS edr_locator,
    f.raw_locator AS fw_locator
FROM edr_activity e
JOIN fw_denies f
    ON e.host_name = f.host_name
WHERE f.event_timestamp >= e.event_timestamp
  AND f.event_timestamp <= e.event_timestamp + INTERVAL '15 minutes'
LIMIT 100;