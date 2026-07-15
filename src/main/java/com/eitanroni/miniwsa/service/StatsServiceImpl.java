package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.AttackerStatsResponse;
import com.eitanroni.miniwsa.api.dto.CategoryStatsResponse;
import com.eitanroni.miniwsa.api.dto.StatsSummaryResponse;
import com.eitanroni.miniwsa.api.dto.TargetedPathStatsResponse;
import com.eitanroni.miniwsa.api.dto.TimeRangeResponse;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import com.eitanroni.miniwsa.persistence.repository.projection.ActionStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.CategoryStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.ClientIpStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.PathStatsProjection;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class StatsServiceImpl implements StatsService {

    private static final int TOP_N = 10;

    private final SecurityEventRepository repository;

    public StatsServiceImpl(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(readOnly = true)
    public StatsSummaryResponse getSummary(Long configId, Instant from, Instant to) {
        long totalEvents = repository.countByReceivedAtRange(configId, from, to);

        // stats by category
        Map<RuleCategory, CategoryStatsResponse> byCategory = new LinkedHashMap<>();
        for (CategoryStatsProjection projection : repository.aggregateByCategory(configId, from, to)) {
            byCategory.put(projection.getCategory(),
                    new CategoryStatsResponse(projection.getCount(), roundAvg(projection.getAvgThreatScore())));
        }

        // stats by action
        Map<Action, Long> byAction = new LinkedHashMap<>();
        for (ActionStatsProjection projection : repository.aggregateByAction(configId, from, to)) {
            byAction.put(projection.getAction(), projection.getCount());
        }

        Pageable topN = PageRequest.of(0, TOP_N);

        // stats by IP
        List<AttackerStatsResponse> topAttackers = repository.findTopAttackers(configId, from, to, topN).stream()
                .map(this::toAttackerStats)
                .toList();

        // stats by path
        List<TargetedPathStatsResponse> topTargetedPaths = repository.findTopTargetedPaths(configId, from, to, topN).stream()
                .map(this::toPathStats)
                .toList();

        return new StatsSummaryResponse(
                configId,
                new TimeRangeResponse(from, to),
                totalEvents,
                byCategory,
                byAction,
                topAttackers,
                topTargetedPaths);
    }

    private AttackerStatsResponse toAttackerStats(ClientIpStatsProjection projection) {
        return new AttackerStatsResponse(projection.getClientIp(), projection.getCount(), roundAvg(projection.getAvgThreatScore()));
    }

    private TargetedPathStatsResponse toPathStats(PathStatsProjection projection) {
        return new TargetedPathStatsResponse(projection.getPath(), projection.getCount());
    }

    // round to one decimal place
    private double roundAvg(Double avg) {
        double value = avg == null ? 0.0 : avg;
        return Math.round(value * 10.0) / 10.0;
    }
}
