package com.eitanroni.miniwsa.api.dto;

public record CategoryStatsResponse(
        long count,
        double avgThreatScore
) {
}
