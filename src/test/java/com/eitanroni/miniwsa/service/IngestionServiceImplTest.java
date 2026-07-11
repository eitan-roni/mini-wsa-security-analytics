package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class IngestionServiceImplTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-07-11T12:00:00Z");

    private SecurityEventRequest sampleEvent(String eventId) {
        return new SecurityEventRequest(
                eventId,
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION),
                Action.DENY,
                new GeoLocationRequest("US", "San Francisco"),
                512L,
                0L
        );
    }

    @Test
    void singleEventProducesSingleResultWithFixedReceivedAt() {
        Clock fixedClock = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);
        IngestionService service = new IngestionServiceImpl(fixedClock);

        EventIngestionResponse response = service.ingest(List.of(sampleEvent("evt-1")));

        assertThat(response.acceptedCount()).isEqualTo(1);
        assertThat(response.events()).hasSize(1);
        assertThat(response.events().get(0).eventId()).isEqualTo("evt-1");
        assertThat(response.events().get(0).receivedAt()).isEqualTo(FIXED_INSTANT);
    }

    @Test
    void assignsFixedClockReceivedAtToEveryEvent() {
        Clock fixedClock = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);
        IngestionService service = new IngestionServiceImpl(fixedClock);

        List<SecurityEventRequest> events = List.of(sampleEvent("evt-1"), sampleEvent("evt-2"));

        EventIngestionResponse response = service.ingest(events);

        assertThat(response.acceptedCount()).isEqualTo(2);
        assertThat(response.events())
                .extracting(result -> result.eventId(), result -> result.receivedAt())
                .containsExactly(
                        tuple("evt-1", FIXED_INSTANT),
                        tuple("evt-2", FIXED_INSTANT)
                );
    }
}
