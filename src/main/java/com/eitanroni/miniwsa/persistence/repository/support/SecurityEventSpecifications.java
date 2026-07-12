package com.eitanroni.miniwsa.persistence.repository.support;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;

/**
 * A predicate is only built for filters that are actually present; a static
 * JPQL query with {@code (:param IS NULL OR ...)} clauses was tried first but
 * PostgreSQL cannot always infer the bind parameter's type from such a
 * clause alone (observed for {@code Instant} and enum-typed parameters,
 * raising "could not determine data type of parameter"), even though the
 * same pattern works for a {@code Long} parameter. Specifications sidestep
 * this entirely by never binding a parameter for an absent filter.
 */
public final class SecurityEventSpecifications {

    private SecurityEventSpecifications() {
    }

    public static Specification<SecurityEventEntity> configIdEquals(Long configId) {
        if (configId == null) {
            return null;
        }
        return (root, query, cb) -> cb.equal(root.get("configId"), configId);
    }

    public static Specification<SecurityEventEntity> eventTimestampFrom(Instant from) {
        if (from == null) {
            return null;
        }
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("eventTimestamp"), from);
    }

    public static Specification<SecurityEventEntity> eventTimestampTo(Instant to) {
        if (to == null) {
            return null;
        }
        return (root, query, cb) -> cb.lessThan(root.get("eventTimestamp"), to);
    }

    public static Specification<SecurityEventEntity> categoryEquals(RuleCategory category) {
        if (category == null) {
            return null;
        }
        return (root, query, cb) -> cb.equal(root.get("category"), category);
    }

    public static Specification<SecurityEventEntity> actionEquals(Action action) {
        if (action == null) {
            return null;
        }
        return (root, query, cb) -> cb.equal(root.get("action"), action);
    }
}
