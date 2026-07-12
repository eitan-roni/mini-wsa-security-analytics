package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.StatsSummaryResponse;

import java.time.Instant;

public interface StatsService {

    StatsSummaryResponse getSummary(Long configId, Instant from, Instant to);
}
