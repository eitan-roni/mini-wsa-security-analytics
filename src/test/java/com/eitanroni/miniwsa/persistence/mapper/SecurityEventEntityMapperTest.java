package com.eitanroni.miniwsa.persistence.mapper;

import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.service.enrichment.EnrichedSecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityEventEntityMapperTest {

    private final SecurityEventEntityMapper mapper = new SecurityEventEntityMapper();

    private SecurityEventRequest requestWith(String userAgent, String city) {
        return new SecurityEventRequest(
                "evt-1",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                userAgent,
                new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION),
                Action.DENY,
                new GeoLocationRequest("US", city),
                512L,
                0L
        );
    }

    private EnrichedSecurityEvent enrichedWith(SecurityEventRequest request, Instant receivedAt) {
        return new EnrichedSecurityEvent(request, receivedAt, "SQL/Command Injection", 75);
    }

    // all them main request fields are correctly copy to the entity
    @Test
    void mapsAllTopLevelFields() {
        Instant receivedAt = Instant.parse("2026-07-11T12:00:00Z");

        SecurityEventEntity entity = mapper.toEntity(
                enrichedWith(requestWith("Mozilla/5.0", "San Francisco"), receivedAt));

        assertThat(entity.getEventId()).isEqualTo("evt-1");
        assertThat(entity.getEventTimestamp()).isEqualTo(Instant.parse("2026-07-11T10:15:30Z"));
        assertThat(entity.getConfigId()).isEqualTo(14227L);
        assertThat(entity.getPolicyId()).isEqualTo("policy-1");
        assertThat(entity.getClientIp()).isEqualTo("203.0.113.10");
        assertThat(entity.getHostname()).isEqualTo("example.com");
        assertThat(entity.getPath()).isEqualTo("/login");
        assertThat(entity.getHttpMethod()).isEqualTo("POST");
        assertThat(entity.getStatusCode()).isEqualTo(403);
        assertThat(entity.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(entity.getAction()).isEqualTo(Action.DENY);
        assertThat(entity.getRequestSize()).isEqualTo(512L);
        assertThat(entity.getResponseSize()).isEqualTo(0L);
    }

    // the mapper convert nested data (from EnrichedSecurityEvent to SecurityEventEntity)
    @Test
    void mapsRuleFields() {
        SecurityEventEntity entity = mapper.toEntity(
                enrichedWith(requestWith("Mozilla/5.0", "San Francisco"), Instant.parse("2026-07-11T12:00:00Z")));

        assertThat(entity.getRuleId()).isEqualTo("950001");
        assertThat(entity.getRuleName()).isEqualTo("SQL_INJECTION");
        assertThat(entity.getRuleMessage()).isEqualTo("SQL Injection Attack Detected");
        assertThat(entity.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(entity.getCategory()).isEqualTo(RuleCategory.INJECTION);
    }

    @Test
    void mapsGeoLocationFields() {
        SecurityEventEntity entity = mapper.toEntity(
                enrichedWith(requestWith("Mozilla/5.0", "San Francisco"), Instant.parse("2026-07-11T12:00:00Z")));

        assertThat(entity.getCountry()).isEqualTo("US");
        assertThat(entity.getCity()).isEqualTo("San Francisco");
    }

    @Test
    void optionalUserAgentAndCityRemainNull() {
        SecurityEventEntity entity = mapper.toEntity(
                enrichedWith(requestWith(null, null), Instant.parse("2026-07-11T12:00:00Z")));

        assertThat(entity.getUserAgent()).isNull();
        assertThat(entity.getCity()).isNull();
    }

    // receivedAt copy to Entity
    @Test
    void mapsReceivedAtExactly() {
        Instant receivedAt = Instant.parse("2026-07-11T12:00:00Z");

        SecurityEventEntity entity = mapper.toEntity(
                enrichedWith(requestWith("Mozilla/5.0", "San Francisco"), receivedAt));

        assertThat(entity.getReceivedAt()).isEqualTo(receivedAt);
    }


    // enrichment fields copy to Entity
    @Test
    void mapsAttackTypeAndThreatScore() {
        SecurityEventRequest request = requestWith("Mozilla/5.0", "San Francisco");
        EnrichedSecurityEvent enrichedEvent = new EnrichedSecurityEvent(
                request, Instant.parse("2026-07-11T12:00:00Z"), "SQL/Command Injection", 75);

        SecurityEventEntity entity = mapper.toEntity(enrichedEvent);

        assertThat(entity.getAttackType()).isEqualTo("SQL/Command Injection");
        assertThat(entity.getThreatScore()).isEqualTo(75);
    }
}
