package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RuleRequest(

        @NotBlank
        String id,

        @NotBlank
        String name,

        @NotBlank
        String message,

        @NotNull
        Severity severity,

        @NotNull
        RuleCategory category
) {
}
