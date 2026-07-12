ALTER TABLE security_events
    ADD COLUMN attack_type  VARCHAR(64),
    ADD COLUMN threat_score INTEGER;

-- Backfill attack_type using the same category mapping as
-- AttackClassificationService.
UPDATE security_events
SET attack_type = CASE category
    WHEN 'INJECTION'          THEN 'SQL/Command Injection'
    WHEN 'XSS'                THEN 'Cross-Site Scripting'
    WHEN 'PROTOCOL_VIOLATION' THEN 'Protocol Anomaly'
    WHEN 'DATA_LEAKAGE'       THEN 'Data Exfiltration'
    WHEN 'BOT'                THEN 'Bot Activity'
    WHEN 'DOS'                THEN 'Denial of Service'
    WHEN 'RATE_LIMIT'         THEN 'Rate Limiting'
END
WHERE attack_type IS NULL;

-- Backfill threat_score using the same severity, action, sensitive-path, and
-- provisional repeat-offender rules as ThreatScoreService/RepeatOffenderService.
--
-- The repeat-offender window count re-uses the existing
-- idx_security_events_client_ip_event_timestamp (client_ip, event_timestamp)
-- index: for each row, it counts how many rows for the same client_ip fall
-- within the inclusive 10-minute window [event_timestamp - 10 minutes,
-- event_timestamp]. Because the window's upper bound is the row's own
-- event_timestamp, this count naturally includes the row itself and only
-- ever looks backward in time, matching the provisional rule
-- "persistedCount + earlierBatchCount + 1 > 5" evaluated over previously
-- persisted rows only.
WITH repeat_offender_window_counts AS (
    SELECT
        e.id,
        (SELECT COUNT(*)
         FROM security_events peer
         WHERE peer.client_ip = e.client_ip
           AND peer.event_timestamp BETWEEN e.event_timestamp - INTERVAL '10 minutes' AND e.event_timestamp
        ) AS window_count
    FROM security_events e
    WHERE e.threat_score IS NULL
)
UPDATE security_events e
SET threat_score = LEAST(
        100,
        CASE e.severity
            WHEN 'CRITICAL' THEN 40
            WHEN 'HIGH'     THEN 30
            WHEN 'MEDIUM'   THEN 20
            WHEN 'LOW'      THEN 10
        END
        +
        CASE e.action
            WHEN 'DENY'    THEN 20
            WHEN 'ALERT'   THEN 10
            WHEN 'MONITOR' THEN 0
        END
        +
        CASE WHEN e.path LIKE '%/admin%' OR e.path LIKE '%/login%' THEN 15 ELSE 0 END
        +
        CASE WHEN roc.window_count > 5 THEN 15 ELSE 0 END
    )
FROM repeat_offender_window_counts roc
WHERE e.id = roc.id;

ALTER TABLE security_events
    ALTER COLUMN attack_type SET NOT NULL,
    ALTER COLUMN threat_score SET NOT NULL;

ALTER TABLE security_events
    ADD CONSTRAINT ck_security_events_threat_score_range CHECK (threat_score BETWEEN 0 AND 100);
