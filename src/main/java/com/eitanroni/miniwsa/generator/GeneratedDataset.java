package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;

import java.util.List;

public record GeneratedDataset(
        List<SecurityEventRequest> events,
        int waveEventCount
) {
}
