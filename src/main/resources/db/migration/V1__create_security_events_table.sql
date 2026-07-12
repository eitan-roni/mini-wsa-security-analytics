CREATE TABLE security_events (
    id                BIGSERIAL PRIMARY KEY,
    event_id          VARCHAR(128)  NOT NULL,
    event_timestamp   TIMESTAMPTZ   NOT NULL,
    received_at       TIMESTAMPTZ   NOT NULL,
    config_id         BIGINT        NOT NULL,
    policy_id         VARCHAR(128)  NOT NULL,
    client_ip         VARCHAR(64)   NOT NULL,
    hostname          VARCHAR(255)  NOT NULL,
    path              VARCHAR(2048) NOT NULL,
    http_method       VARCHAR(16)   NOT NULL,
    status_code       INTEGER       NOT NULL,
    user_agent        VARCHAR(512),
    rule_id           VARCHAR(128)  NOT NULL,
    rule_name         VARCHAR(255)  NOT NULL,
    rule_message      VARCHAR(1024) NOT NULL,
    severity          VARCHAR(32)   NOT NULL,
    category          VARCHAR(32)   NOT NULL,
    action            VARCHAR(32)   NOT NULL,
    country           VARCHAR(8)    NOT NULL,
    city              VARCHAR(255),
    request_size      BIGINT        NOT NULL,
    response_size     BIGINT        NOT NULL,

    CONSTRAINT uq_security_events_event_id UNIQUE (event_id),
    CONSTRAINT ck_security_events_config_id_positive CHECK (config_id > 0),
    CONSTRAINT ck_security_events_status_code_range CHECK (status_code BETWEEN 100 AND 599),
    CONSTRAINT ck_security_events_request_size_non_negative CHECK (request_size >= 0),
    CONSTRAINT ck_security_events_response_size_non_negative CHECK (response_size >= 0)
);

CREATE INDEX idx_security_events_config_id_event_timestamp
    ON security_events (config_id, event_timestamp DESC);

CREATE INDEX idx_security_events_client_ip_event_timestamp
    ON security_events (client_ip, event_timestamp DESC);

CREATE INDEX idx_security_events_event_timestamp
    ON security_events (event_timestamp DESC);
