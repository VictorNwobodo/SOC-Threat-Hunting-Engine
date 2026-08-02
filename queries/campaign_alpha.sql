WITH auth_success AS (
    SELECT event_id, actor_user, source_ip, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'auth' 
      AND event_action = 'login_success'
      AND actor_user IS NOT NULL
),
edr_starts AS (
    SELECT event_id, actor_user, host_name, event_timestamp, raw_locator
    FROM normalized_events
    WHERE source_type = 'endpoint' 
      AND event_action = 'process_start'
      AND actor_user IS NOT NULL
)
SELECT 
    a.event_id AS auth_event_id,
    a.actor_user AS actor,
    a.source_ip AS source_ip,
    e.event_id AS edr_event_id,
    e.host_name AS host_name,
    a.event_timestamp AS auth_time,
    e.event_timestamp AS edr_time,
    a.raw_locator AS auth_locator,
    e.raw_locator AS edr_locator
FROM auth_success a
JOIN edr_starts e 
    ON a.actor_user = e.actor_user 
WHERE e.event_timestamp >= a.event_timestamp
  AND e.event_timestamp <= a.event_timestamp + INTERVAL '10 minutes'
LIMIT 100;