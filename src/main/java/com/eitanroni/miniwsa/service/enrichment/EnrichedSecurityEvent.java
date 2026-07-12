package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;

import java.time.Instant;

/**
 * Internal domain model produced by the enrichment pipeline. Not exposed
 * directly by the REST API.
 */
public record EnrichedSecurityEvent(
        SecurityEventRequest original,
        Instant receivedAt,
        String attackType,
        int threatScore
) {
}
