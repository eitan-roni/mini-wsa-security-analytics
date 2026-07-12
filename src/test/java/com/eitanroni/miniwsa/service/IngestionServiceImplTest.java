package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.mapper.SecurityEventEntityMapper;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import com.eitanroni.miniwsa.service.enrichment.AttackClassificationService;
import com.eitanroni.miniwsa.service.enrichment.EventEnrichmentService;
import com.eitanroni.miniwsa.service.enrichment.RepeatOffenderService;
import com.eitanroni.miniwsa.service.enrichment.ThreatScoreService;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IngestionServiceImplTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-07-11T12:00:00Z");

    @Mock
    private SecurityEventRepository repository;

    private final SecurityEventEntityMapper mapper = new SecurityEventEntityMapper();

    private IngestionServiceImpl service() {
        Clock fixedClock = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);
        EventEnrichmentService enrichmentService = new EventEnrichmentService(
                new AttackClassificationService(),
                new ThreatScoreService(),
                new RepeatOffenderService(repository));
        return new IngestionServiceImpl(fixedClock, repository, mapper, enrichmentService);
    }

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

    @SuppressWarnings("unchecked")
    private void stubSuccessfulSave() {
        when(repository.saveAllAndFlush(anyList()))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void singleEventIsPersisted() {
        stubSuccessfulSave();

        EventIngestionResponse response = service().ingest(List.of(sampleEvent("evt-1")));

        ArgumentCaptor<List<SecurityEventEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository).saveAllAndFlush(captor.capture());

        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).getEventId()).isEqualTo("evt-1");
        assertThat(response.acceptedCount()).isEqualTo(1);
    }

    @Test
    void batchIsPersistedInOneRepositoryOperation() {
        stubSuccessfulSave();

        List<SecurityEventRequest> events = List.of(sampleEvent("evt-1"), sampleEvent("evt-2"), sampleEvent("evt-3"));

        service().ingest(events);

        ArgumentCaptor<List<SecurityEventEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository, times(1)).saveAllAndFlush(captor.capture());
        assertThat(captor.getValue()).hasSize(3);
    }

    @Test
    void sameFixedReceivedAtIsUsedForEveryEventInBatch() {
        stubSuccessfulSave();

        List<SecurityEventRequest> events = List.of(sampleEvent("evt-1"), sampleEvent("evt-2"));

        EventIngestionResponse response = service().ingest(events);

        ArgumentCaptor<List<SecurityEventEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository).saveAllAndFlush(captor.capture());

        assertThat(captor.getValue())
                .extracting(SecurityEventEntity::getReceivedAt)
                .containsOnly(FIXED_INSTANT);
        assertThat(response.events())
                .extracting(result -> result.receivedAt())
                .containsOnly(FIXED_INSTANT);
    }

    @Test
    void responseRetainsInputOrder() {
        stubSuccessfulSave();

        List<SecurityEventRequest> events = List.of(sampleEvent("evt-3"), sampleEvent("evt-1"), sampleEvent("evt-2"));

        EventIngestionResponse response = service().ingest(events);

        assertThat(response.events())
                .extracting(result -> result.eventId())
                .containsExactly("evt-3", "evt-1", "evt-2");
    }

    @Test
    void entitiesArePersistedWithAttackTypeAndThreatScoreAlreadyEnriched() {
        stubSuccessfulSave();

        service().ingest(List.of(sampleEvent("evt-1")));

        ArgumentCaptor<List<SecurityEventEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(repository).saveAllAndFlush(captor.capture());

        SecurityEventEntity entity = captor.getValue().get(0);
        assertThat(entity.getAttackType()).isEqualTo("SQL/Command Injection");
        assertThat(entity.getThreatScore()).isEqualTo(75); // CRITICAL(40) + DENY(20) + /login(15)
    }

    @Test
    void responseCountMatchesInputCount() {
        stubSuccessfulSave();

        List<SecurityEventRequest> events = List.of(sampleEvent("evt-1"), sampleEvent("evt-2"), sampleEvent("evt-3"));

        EventIngestionResponse response = service().ingest(events);

        assertThat(response.acceptedCount()).isEqualTo(3);
        assertThat(response.events()).hasSize(3);
    }

    @Test
    @SuppressWarnings("unchecked")
    void duplicateDatabaseViolationIsConvertedToDuplicateEventException() {
        ConstraintViolationException constraintViolation = new ConstraintViolationException(
                "duplicate key value violates unique constraint",
                new SQLException("duplicate key value violates unique constraint \"uq_security_events_event_id\""),
                "uq_security_events_event_id");
        DataIntegrityViolationException dbException = new DataIntegrityViolationException("insert failed", constraintViolation);

        when(repository.saveAllAndFlush(anyList())).thenThrow(dbException);

        assertThatThrownBy(() -> service().ingest(List.of(sampleEvent("evt-1"))))
                .isInstanceOf(DuplicateEventException.class)
                .hasCauseReference(dbException);
    }

    @Test
    @SuppressWarnings("unchecked")
    void unexpectedDatabaseErrorsAreNotIncorrectlyReportedAsDuplicates() {
        ConstraintViolationException constraintViolation = new ConstraintViolationException(
                "value too long for type character varying(128)",
                new SQLException("value too long for type character varying(128)"),
                "ck_security_events_status_code_range");
        DataIntegrityViolationException dbException = new DataIntegrityViolationException("insert failed", constraintViolation);

        when(repository.saveAllAndFlush(anyList())).thenThrow(dbException);

        assertThatThrownBy(() -> service().ingest(List.of(sampleEvent("evt-1"))))
                .isSameAs(dbException);
    }
}
