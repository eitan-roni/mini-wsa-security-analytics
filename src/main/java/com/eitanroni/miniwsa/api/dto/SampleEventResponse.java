package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.Action;

import java.time.Instant;

public record SampleEventResponse(
        String eventId,
        Instant timestamp,
        Long configId,
        String policyId,
        String clientIp,
        String hostname,
        String path,
        String method,
        Integer statusCode,
        String userAgent,
        RuleResponse rule,
        Action action,
        GeoLocationResponse geoLocation,
        Long requestSize,
        Long responseSize,
        Instant receivedAt,
        String attackType,
        Integer threatScore
) {
}
