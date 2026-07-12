package com.eitanroni.miniwsa.api.dto;

import java.util.List;

public record SampleSearchResponse(
        long totalCount,
        int limit,
        int offset,
        List<SampleEventResponse> events
) {
}
