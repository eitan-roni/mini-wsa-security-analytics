package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EventEnrichmentServiceTest {

    private static final Instant RECEIVED_AT = Instant.parse("2026-07-11T12:00:00Z");

    @Mock
    private SecurityEventRepository repository;

    private EventEnrichmentService service() {
        when(repository.countByClientIpAndEventTimestampBetween(anyString(), any(), any())).thenReturn(0L);
        return new EventEnrichmentService(
                new AttackClassificationService(),
                new ThreatScoreService(),
                new RepeatOffenderService(repository));
    }

    private SecurityEventRequest eventAt(String eventId, String path, Action action, Severity severity, RuleCategory category) {
        return new SecurityEventRequest(
                eventId,
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                path,
                "POST",
                403,
                "Mozilla/5.0",
                new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", severity, category),
                action,
                new GeoLocationRequest("US", "San Francisco"),
                512L,
                0L
        );
    }

    @Test
    void enrichesEveryEventWithClassificationAndScore() {
        SecurityEventRequest event = eventAt("evt-1", "/login", Action.DENY, Severity.CRITICAL, RuleCategory.INJECTION);

        List<EnrichedSecurityEvent> enriched = service().enrich(List.of(event), RECEIVED_AT);

        assertThat(enriched).hasSize(1);
        assertThat(enriched.get(0).original()).isEqualTo(event);
        assertThat(enriched.get(0).receivedAt()).isEqualTo(RECEIVED_AT);
        assertThat(enriched.get(0).attackType()).isEqualTo("SQL/Command Injection");
        assertThat(enriched.get(0).threatScore()).isEqualTo(75); // 40 + 20 + 15, not a repeat offender
    }

    @Test
    void preservesOriginalRequestOrder() {
        List<SecurityEventRequest> events = List.of(
                eventAt("evt-3", "/a", Action.MONITOR, Severity.LOW, RuleCategory.BOT),
                eventAt("evt-1", "/b", Action.MONITOR, Severity.LOW, RuleCategory.BOT),
                eventAt("evt-2", "/c", Action.MONITOR, Severity.LOW, RuleCategory.BOT)
        );

        List<EnrichedSecurityEvent> enriched = service().enrich(events, RECEIVED_AT);

        assertThat(enriched)
                .extracting(e -> e.original().eventId())
                .containsExactly("evt-3", "evt-1", "evt-2");
    }

    @Test
    void sameReceivedAtIsAppliedToEveryEnrichedEvent() {
        List<SecurityEventRequest> events = List.of(
                eventAt("evt-1", "/a", Action.MONITOR, Severity.LOW, RuleCategory.BOT),
                eventAt("evt-2", "/b", Action.MONITOR, Severity.LOW, RuleCategory.BOT)
        );

        List<EnrichedSecurityEvent> enriched = service().enrich(events, RECEIVED_AT);

        assertThat(enriched).extracting(EnrichedSecurityEvent::receivedAt).containsOnly(RECEIVED_AT);
    }
}
