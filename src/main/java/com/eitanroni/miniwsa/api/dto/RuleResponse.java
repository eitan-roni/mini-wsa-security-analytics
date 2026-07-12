package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;

public record RuleResponse(
        String id,
        String name,
        String message,
        Severity severity,
        RuleCategory category
) {
}
