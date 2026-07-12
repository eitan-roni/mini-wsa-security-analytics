package com.eitanroni.miniwsa.persistence.repository.support;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityEventSpecificationsTest {

    @Mock
    private Root<SecurityEventEntity> root;

    @Mock
    private CriteriaQuery<?> query;

    @Mock
    private CriteriaBuilder criteriaBuilder;

    @Mock
    @SuppressWarnings("rawtypes")
    private Path path;

    @Mock
    private Predicate predicate;

    @Test
    void configIdEqualsReturnsNullSpecificationWhenConfigIdIsAbsent() {
        assertThat(SecurityEventSpecifications.configIdEquals(null)).isNull();
    }

    @Test
    void configIdEqualsBuildsEqualityPredicateWhenPresent() {
        when(root.get("configId")).thenReturn(path);
        when(criteriaBuilder.equal(path, 14227L)).thenReturn(predicate);

        Specification<SecurityEventEntity> spec = SecurityEventSpecifications.configIdEquals(14227L);

        assertThat(spec).isNotNull();
        assertThat(spec.toPredicate(root, query, criteriaBuilder)).isSameAs(predicate);
    }

    @Test
    void eventTimestampFromReturnsNullSpecificationWhenAbsent() {
        assertThat(SecurityEventSpecifications.eventTimestampFrom(null)).isNull();
    }

    @Test
    void eventTimestampFromBuildsGreaterThanOrEqualToPredicateWhenPresent() {
        Instant from = Instant.parse("2026-07-01T00:00:00Z");
        when(root.get("eventTimestamp")).thenReturn(path);
        when(criteriaBuilder.greaterThanOrEqualTo(path, from)).thenReturn(predicate);

        Specification<SecurityEventEntity> spec = SecurityEventSpecifications.eventTimestampFrom(from);

        assertThat(spec).isNotNull();
        assertThat(spec.toPredicate(root, query, criteriaBuilder)).isSameAs(predicate);
    }

    @Test
    void eventTimestampToReturnsNullSpecificationWhenAbsent() {
        assertThat(SecurityEventSpecifications.eventTimestampTo(null)).isNull();
    }

    @Test
    void eventTimestampToBuildsLessThanPredicateWhenPresent() {
        Instant to = Instant.parse("2026-07-02T00:00:00Z");
        when(root.get("eventTimestamp")).thenReturn(path);
        when(criteriaBuilder.lessThan(path, to)).thenReturn(predicate);

        Specification<SecurityEventEntity> spec = SecurityEventSpecifications.eventTimestampTo(to);

        assertThat(spec).isNotNull();
        assertThat(spec.toPredicate(root, query, criteriaBuilder)).isSameAs(predicate);
    }

    @Test
    void categoryEqualsReturnsNullSpecificationWhenAbsent() {
        assertThat(SecurityEventSpecifications.categoryEquals(null)).isNull();
    }

    @Test
    void categoryEqualsBuildsEqualityPredicateWhenPresent() {
        when(root.get("category")).thenReturn(path);
        when(criteriaBuilder.equal(path, RuleCategory.INJECTION)).thenReturn(predicate);

        Specification<SecurityEventEntity> spec = SecurityEventSpecifications.categoryEquals(RuleCategory.INJECTION);

        assertThat(spec).isNotNull();
        assertThat(spec.toPredicate(root, query, criteriaBuilder)).isSameAs(predicate);
    }

    @Test
    void actionEqualsReturnsNullSpecificationWhenAbsent() {
        assertThat(SecurityEventSpecifications.actionEquals(null)).isNull();
    }

    @Test
    void actionEqualsBuildsEqualityPredicateWhenPresent() {
        when(root.get("action")).thenReturn(path);
        when(criteriaBuilder.equal(path, Action.DENY)).thenReturn(predicate);

        Specification<SecurityEventEntity> spec = SecurityEventSpecifications.actionEquals(Action.DENY);

        assertThat(spec).isNotNull();
        assertThat(spec.toPredicate(root, query, criteriaBuilder)).isSameAs(predicate);
    }
}
