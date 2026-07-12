package com.eitanroni.miniwsa.api.dto;

import java.util.List;

public record EventIngestionResponse(
        int acceptedCount,
        List<IngestedEventResult> events
) {
}
