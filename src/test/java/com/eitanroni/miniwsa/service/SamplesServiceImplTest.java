package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.SampleSearchResponse;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamplesServiceImplTest {

    private static final Instant FROM = Instant.parse("2026-07-01T00:00:00Z");

    @Mock
    private SecurityEventRepository repository;

    private SamplesServiceImpl service() {
        return new SamplesServiceImpl(repository);
    }

    private SecurityEventEntity entity(String eventId, Instant eventTimestamp, Instant receivedAt) {
        return new SecurityEventEntity(
                eventId,
                eventTimestamp,
                receivedAt,
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                "950001",
                "SQL_INJECTION",
                "SQL Injection Attack Detected",
                Severity.CRITICAL,
                RuleCategory.INJECTION,
                Action.DENY,
                "US",
                "San Francisco",
                512L,
                0L,
                "SQL/Command Injection",
                75);
    }

    @SuppressWarnings("unchecked")
    private void stubFindAll(List<SecurityEventEntity> content, long totalElements) {
        when(repository.findAll(any(Specification.class), any(Pageable.class)))
                .thenAnswer(invocation -> new PageImpl<>(content, invocation.getArgument(1), totalElements));
    }

    // Verifies that the service builds a search specification and passes it to the repository
    @Test
    void searchBuildsASpecificationAndDelegatesToRepositoryFindAll() {
        stubFindAll(List.of(), 0);
        SampleSearchCriteria criteria =
                new SampleSearchCriteria(14227L, FROM, null, RuleCategory.BOT, Action.MONITOR, 20, 0);

        service().search(criteria);

        ArgumentCaptor<Specification<SecurityEventEntity>> specCaptor = ArgumentCaptor.forClass(Specification.class);
        verify(repository).findAll(specCaptor.capture(), any(Pageable.class));
        assertThat(specCaptor.getValue()).isNotNull();
    }

    // OffsetBasedPageable is correctly used
    @Test
    void pageableReflectsCriteriaLimitAndOffsetNotPageNumber() {
        stubFindAll(List.of(), 0);
        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 3, 2);

        service().search(criteria);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(repository).findAll(any(Specification.class), pageableCaptor.capture());

        Pageable pageable = pageableCaptor.getValue();
        assertThat(pageable.getOffset()).isEqualTo(2L);
        assertThat(pageable.getPageSize()).isEqualTo(3);
    }

    // Verifies that a limit of 100 is correctly applied as the pageable page size
    @Test
    void maximumLimitOfOneHundredIsHonoredInPageable() {
        stubFindAll(List.of(), 0);
        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 100, 0);

        service().search(criteria);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(repository).findAll(any(Specification.class), pageableCaptor.capture());

        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(100);
    }

    // Verifies that sample events are sorted by eventTimestamp in descending order,
    // and by id in descending order when timestamps are equal
    @Test
    void pageableSortsByEventTimestampDescendingThenIdDescending() {
        stubFindAll(List.of(), 0);
        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 20, 0);

        service().search(criteria);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(repository).findAll(any(Specification.class), pageableCaptor.capture());

        var orders = pageableCaptor.getValue().getSort().toList();
        assertThat(orders).hasSize(2);
        assertThat(orders.get(0).getProperty()).isEqualTo("eventTimestamp");
        assertThat(orders.get(0).isDescending()).isTrue();
        assertThat(orders.get(1).getProperty()).isEqualTo("id");
        assertThat(orders.get(1).isDescending()).isTrue();
    }

    // Verifies that totalCount represents all matching records before pagination,
    // not only the events returned in the current page.
    @Test
    void totalCountReflectsCountBeforePaginationNotPageSize() {
        stubFindAll(List.of(entity("evt-1", FROM, FROM)), 57);
        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 20, 0);

        SampleSearchResponse response = service().search(criteria);

        assertThat(response.totalCount()).isEqualTo(57L);
        assertThat(response.events()).hasSize(1);
    }

    // Verifies that an empty repository result produces an empty event list and a total count of zero
    @Test
    void emptyResultProducesEmptyEventsListAndZeroTotalCount() {
        stubFindAll(List.of(), 0);
        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 20, 0);

        SampleSearchResponse response = service().search(criteria);

        assertThat(response.totalCount()).isZero();
        assertThat(response.events()).isEmpty();
        assertThat(response.limit()).isEqualTo(20);
        assertThat(response.offset()).isEqualTo(0);
    }

    // Verifies that all original and enriched entity fields are correctly mapped to the API response
    @Test
    void responseMapsOriginalAndEnrichedFieldsFromEntity() {
        Instant eventTimestamp = Instant.parse("2026-07-01T10:00:00Z");
        Instant receivedAt = Instant.parse("2026-07-01T10:00:01Z");
        stubFindAll(List.of(entity("evt-1", eventTimestamp, receivedAt)), 1);

        SampleSearchCriteria criteria = new SampleSearchCriteria(null, null, null, null, null, 20, 0);

        SampleSearchResponse response = service().search(criteria);

        var event = response.events().get(0);
        assertThat(event.eventId()).isEqualTo("evt-1");
        assertThat(event.timestamp()).isEqualTo(eventTimestamp);
        assertThat(event.configId()).isEqualTo(14227L);
        assertThat(event.policyId()).isEqualTo("policy-1");
        assertThat(event.clientIp()).isEqualTo("203.0.113.10");
        assertThat(event.hostname()).isEqualTo("example.com");
        assertThat(event.path()).isEqualTo("/login");
        assertThat(event.method()).isEqualTo("POST");
        assertThat(event.statusCode()).isEqualTo(403);
        assertThat(event.userAgent()).isEqualTo("Mozilla/5.0");
        assertThat(event.rule().id()).isEqualTo("950001");
        assertThat(event.rule().name()).isEqualTo("SQL_INJECTION");
        assertThat(event.rule().message()).isEqualTo("SQL Injection Attack Detected");
        assertThat(event.rule().severity()).isEqualTo(Severity.CRITICAL);
        assertThat(event.rule().category()).isEqualTo(RuleCategory.INJECTION);
        assertThat(event.action()).isEqualTo(Action.DENY);
        assertThat(event.geoLocation().country()).isEqualTo("US");
        assertThat(event.geoLocation().city()).isEqualTo("San Francisco");
        assertThat(event.requestSize()).isEqualTo(512L);
        assertThat(event.responseSize()).isEqualTo(0L);
        assertThat(event.receivedAt()).isEqualTo(receivedAt);
        assertThat(event.attackType()).isEqualTo("SQL/Command Injection");
        assertThat(event.threatScore()).isEqualTo(75);
    }
}
