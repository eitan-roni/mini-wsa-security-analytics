package com.eitanroni.miniwsa.api.dto;

public record AttackerStatsResponse(
        String clientIp,
        long count,
        double avgThreatScore
) {
}
