package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.Action;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

import java.time.Instant;

public record SecurityEventRequest(

        @NotBlank
        String eventId,

        @NotNull
        Instant timestamp,

        @NotBlank
        String configId,

        @NotBlank
        String policyId,

        @NotBlank
        String clientIp,

        @NotBlank
        String hostname,

        @NotBlank
        String path,

        @NotBlank
        String method,

        @NotNull
        Integer statusCode,

        String userAgent,

        @NotNull
        @Valid
        RuleRequest rule,

        @NotNull
        Action action,

        @NotNull
        @Valid
        GeoLocationRequest geoLocation,

        @NotNull
        @PositiveOrZero
        Long requestSize,

        @NotNull
        @PositiveOrZero
        Long responseSize
) {
}