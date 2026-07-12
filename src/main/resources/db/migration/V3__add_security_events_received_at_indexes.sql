-- The v0.3-stats summary endpoint filters exclusively by received_at
-- (optionally scoped to config_id), a column that none of the V1 indexes
-- cover (they are all keyed on event_timestamp). Without these indexes,
-- every stats query would require a full table scan of security_events.
CREATE INDEX idx_security_events_config_id_received_at
    ON security_events (config_id, received_at);

CREATE INDEX idx_security_events_received_at
    ON security_events (received_at);