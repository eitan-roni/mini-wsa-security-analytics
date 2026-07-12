package com.eitanroni.miniwsa.persistence.entity;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "security_events")
public class SecurityEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "event_id", length = 128, nullable = false)
    private String eventId;

    @Column(name = "event_timestamp", nullable = false)
    private Instant eventTimestamp;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    @Column(name = "config_id", nullable = false)
    private Long configId;

    @Column(name = "policy_id", length = 128, nullable = false)
    private String policyId;

    @Column(name = "client_ip", length = 64, nullable = false)
    private String clientIp;

    @Column(name = "hostname", length = 255, nullable = false)
    private String hostname;

    @Column(name = "path", length = 2048, nullable = false)
    private String path;

    @Column(name = "http_method", length = 16, nullable = false)
    private String httpMethod;

    @Column(name = "status_code", nullable = false)
    private Integer statusCode;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "rule_id", length = 128, nullable = false)
    private String ruleId;

    @Column(name = "rule_name", length = 255, nullable = false)
    private String ruleName;

    @Column(name = "rule_message", length = 1024, nullable = false)
    private String ruleMessage;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", length = 32, nullable = false)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "category", length = 32, nullable = false)
    private RuleCategory category;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", length = 32, nullable = false)
    private Action action;

    @Column(name = "country", length = 8, nullable = false)
    private String country;

    @Column(name = "city", length = 255)
    private String city;

    @Column(name = "request_size", nullable = false)
    private Long requestSize;

    @Column(name = "response_size", nullable = false)
    private Long responseSize;

    @Column(name = "attack_type", length = 64, nullable = false)
    private String attackType;

    @Column(name = "threat_score", nullable = false)
    private Integer threatScore;

    protected SecurityEventEntity() {
        // required by JPA
    }

    public SecurityEventEntity(String eventId,
                                Instant eventTimestamp,
                                Instant receivedAt,
                                Long configId,
                                String policyId,
                                String clientIp,
                                String hostname,
                                String path,
                                String httpMethod,
                                Integer statusCode,
                                String userAgent,
                                String ruleId,
                                String ruleName,
                                String ruleMessage,
                                Severity severity,
                                RuleCategory category,
                                Action action,
                                String country,
                                String city,
                                Long requestSize,
                                Long responseSize,
                                String attackType,
                                Integer threatScore) {
        this.eventId = eventId;
        this.eventTimestamp = eventTimestamp;
        this.receivedAt = receivedAt;
        this.configId = configId;
        this.policyId = policyId;
        this.clientIp = clientIp;
        this.hostname = hostname;
        this.path = path;
        this.httpMethod = httpMethod;
        this.statusCode = statusCode;
        this.userAgent = userAgent;
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.ruleMessage = ruleMessage;
        this.severity = severity;
        this.category = category;
        this.action = action;
        this.country = country;
        this.city = city;
        this.requestSize = requestSize;
        this.responseSize = responseSize;
        this.attackType = attackType;
        this.threatScore = threatScore;
    }

    public Long getId() {
        return id;
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getEventTimestamp() {
        return eventTimestamp;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }

    public Long getConfigId() {
        return configId;
    }

    public String getPolicyId() {
        return policyId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getHostname() {
        return hostname;
    }

    public String getPath() {
        return path;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getRuleMessage() {
        return ruleMessage;
    }

    public Severity getSeverity() {
        return severity;
    }

    public RuleCategory getCategory() {
        return category;
    }

    public Action getAction() {
        return action;
    }

    public String getCountry() {
        return country;
    }

    public String getCity() {
        return city;
    }

    public Long getRequestSize() {
        return requestSize;
    }

    public Long getResponseSize() {
        return responseSize;
    }

    public String getAttackType() {
        return attackType;
    }

    public Integer getThreatScore() {
        return threatScore;
    }
}
