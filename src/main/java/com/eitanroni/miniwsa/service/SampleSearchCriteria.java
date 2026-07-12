package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;

import java.time.Instant;

public record SampleSearchCriteria(
        Long configId,
        Instant from,
        Instant to,
        RuleCategory category,
        Action action,
        int limit,
        int offset
) {
}
