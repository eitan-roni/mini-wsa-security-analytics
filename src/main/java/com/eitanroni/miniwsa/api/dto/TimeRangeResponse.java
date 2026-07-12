package com.eitanroni.miniwsa.api.dto;

import java.time.Instant;

public record TimeRangeResponse(
        Instant from,
        Instant to
) {
}
