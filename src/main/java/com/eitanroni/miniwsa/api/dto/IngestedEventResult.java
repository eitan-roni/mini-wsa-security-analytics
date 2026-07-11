package com.eitanroni.miniwsa.api.dto;

import java.time.Instant;

public record IngestedEventResult(
        String eventId,
        Instant receivedAt
) {
}
