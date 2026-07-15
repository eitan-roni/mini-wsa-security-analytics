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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RepeatOffenderServiceTest {

    private static final Instant T0 = Instant.parse("2026-07-11T10:00:00Z");
    private static final String IP_A = "203.0.113.10";
    private static final String IP_B = "203.0.113.20";

    @Mock
    private SecurityEventRepository repository;

    private RepeatOffenderService service() {
        return new RepeatOffenderService(repository);
    }

    private void stubNoPersistedEvents() {
        when(repository.countByClientIpAndEventTimestampBetween(anyString(), any(), any())).thenReturn(0L);
    }

    private SecurityEventRequest eventAt(String eventId, String clientIp, Instant timestamp) {
        return new SecurityEventRequest(
                eventId,
                timestamp,
                14227L,
                "policy-1",
                clientIp,
                "example.com",
                "/checkout",
                "POST",
                200,
                "Mozilla/5.0",
                new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION),
                Action.DENY,
                new GeoLocationRequest("US", "San Francisco"),
                512L,
                0L
        );
    }

    // only 5 events - there is no bonus at all
    @Test
    void fiveTotalEventsDoNotReceiveBonus() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-1", IP_A, T0),
                eventAt("evt-2", IP_A, T0.plusSeconds(60)),
                eventAt("evt-3", IP_A, T0.plusSeconds(120)),
                eventAt("evt-4", IP_A, T0.plusSeconds(180)),
                eventAt("evt-5", IP_A, T0.plusSeconds(240))
        );

        List<Boolean> results = service().evaluateBatch(events);

        assertThat(results).containsExactly(false, false, false, false, false);
    }

    // only the sixth event get a bonus (false, false, false, false, false, true)
    @Test
    void sixthEventReceivesBonus() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-1", IP_A, T0),
                eventAt("evt-2", IP_A, T0.plusSeconds(60)),
                eventAt("evt-3", IP_A, T0.plusSeconds(120)),
                eventAt("evt-4", IP_A, T0.plusSeconds(180)),
                eventAt("evt-5", IP_A, T0.plusSeconds(240)),
                eventAt("evt-6", IP_A, T0.plusSeconds(300))
        );

        List<Boolean> results = service().evaluateBatch(events);

        assertThat(results).containsExactly(false, false, false, false, false, true);
    }

    // Verifies that an event exactly ten minutes old is still included in the repeat-offender time window
    @Test
    void eventExactlyTenMinutesOldIsIncluded() {
        when(repository.countByClientIpAndEventTimestampBetween(anyString(), any(), any())).thenReturn(4L);

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-earlier", IP_A, T0),
                eventAt("evt-current", IP_A, T0.plus(java.time.Duration.ofMinutes(10)))
        );

        List<Boolean> results = service().evaluateBatch(events);

        // background persisted count (4) + this earlier batch event (1) + itself (1) = 6 > 5
        assertThat(results.get(1)).isTrue();
    }

    // Verifies that an event older than ten minutes is excluded from the repeat-offender window
    @Test
    void eventOlderThanTenMinutesIsExcluded() {
        when(repository.countByClientIpAndEventTimestampBetween(anyString(), any(), any())).thenReturn(4L);

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-earlier", IP_A, T0),
                eventAt("evt-current", IP_A, T0.plus(java.time.Duration.ofMinutes(10)).plusSeconds(1))
        );

        List<Boolean> results = service().evaluateBatch(events);

        // background persisted count (4) + itself (1) = 5, not > 5, because evt-earlier falls
        // just outside the window and is excluded
        assertThat(results.get(1)).isFalse();
    }

    // the sixth event in the batch belong to different IP - there is no bonus
    @Test
    void eventsFromAnotherIpAreExcluded() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-a1", IP_A, T0),
                eventAt("evt-a2", IP_A, T0.plusSeconds(60)),
                eventAt("evt-a3", IP_A, T0.plusSeconds(120)),
                eventAt("evt-a4", IP_A, T0.plusSeconds(180)),
                eventAt("evt-b1", IP_B, T0.plusSeconds(200)),
                eventAt("evt-a-current", IP_A, T0.plusSeconds(240))
        );

        List<Boolean> results = service().evaluateBatch(events);

        // Only 4 earlier same-IP events + itself = 5, not > 5, even though 6 events
        // exist in the batch overall.
        assertThat(results.get(5)).isFalse();
    }

    @Test
    void earlierEventsInSameBatchAreCounted() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-1", IP_A, T0),
                eventAt("evt-2", IP_A, T0.plusSeconds(60)),
                eventAt("evt-3", IP_A, T0.plusSeconds(120)),
                eventAt("evt-4", IP_A, T0.plusSeconds(180)),
                eventAt("evt-5", IP_A, T0.plusSeconds(240)),
                eventAt("evt-6", IP_A, T0.plusSeconds(300))
        );

        List<Boolean> results = service().evaluateBatch(events);

        assertThat(results.get(5)).isTrue();
    }

    // Verifies that events are processed by their timestamp, not by the order they appear in the batch.
    @Test
    void batchInputOrderDoesNotOverrideEventTimestampOrder() {
        stubNoPersistedEvents();

        // Submitted in reverse-chronological order; the sixth event by
        // event-timestamp ("evt-newest") is placed first in the request.
        List<SecurityEventRequest> events = List.of(
                eventAt("evt-newest", IP_A, T0.plusSeconds(300)),
                eventAt("evt-5", IP_A, T0.plusSeconds(240)),
                eventAt("evt-4", IP_A, T0.plusSeconds(180)),
                eventAt("evt-3", IP_A, T0.plusSeconds(120)),
                eventAt("evt-2", IP_A, T0.plusSeconds(60)),
                eventAt("evt-oldest", IP_A, T0)
        );

        List<Boolean> results = service().evaluateBatch(events);

        // "evt-newest" is chronologically last (6th), so it -- not the first
        // list element by coincidence -- receives the bonus, at its original
        // request index (0).
        assertThat(results.get(0)).isTrue();
        assertThat(results.subList(1, 6)).containsOnly(false);
    }

    // Verifies that when events have the same timestamp,
    // they are processed in the order they appear in the batch.
    @Test
    void equalTimestampsUseRequestOrderAsTieBreaker() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(
                eventAt("evt-1", IP_A, T0),
                eventAt("evt-2", IP_A, T0),
                eventAt("evt-3", IP_A, T0),
                eventAt("evt-4", IP_A, T0),
                eventAt("evt-5", IP_A, T0),
                eventAt("evt-6", IP_A, T0)
        );

        List<Boolean> results = service().evaluateBatch(events);

        assertThat(results).containsExactly(false, false, false, false, false, true);
    }

    // Verifies that a late event does not update events that were already saved
    @Test
    void lateEventDoesNotTriggerRecalculationOfAlreadyStoredEvents() {
        stubNoPersistedEvents();

        List<SecurityEventRequest> events = List.of(eventAt("evt-late", IP_A, T0));

        service().evaluateBatch(events);

        verify(repository).countByClientIpAndEventTimestampBetween(anyString(), any(), any());
        verify(repository, never()).save(any());
        verify(repository, never()).saveAll(any());
        verify(repository, never()).saveAndFlush(any());
        verify(repository, never()).saveAllAndFlush(any());
        verifyNoMoreInteractions(repository);
    }
}
