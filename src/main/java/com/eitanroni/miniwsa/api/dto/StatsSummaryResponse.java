package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;

import java.util.List;
import java.util.Map;

public record StatsSummaryResponse(
        Long configId,
        TimeRangeResponse timeRange,
        long totalEvents,
        Map<RuleCategory, CategoryStatsResponse> byCategory,
        Map<Action, Long> byAction,
        List<AttackerStatsResponse> topAttackers,
        List<TargetedPathStatsResponse> topTargetedPaths
) {
}
