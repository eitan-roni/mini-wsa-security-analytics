package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.AttackerStatsResponse;
import com.eitanroni.miniwsa.api.dto.CategoryStatsResponse;
import com.eitanroni.miniwsa.api.dto.StatsSummaryResponse;
import com.eitanroni.miniwsa.api.dto.TargetedPathStatsResponse;
import com.eitanroni.miniwsa.api.dto.TimeRangeResponse;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.service.StatsService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(StatsController.class)
class StatsControllerTest {

    private static final String SUMMARY_URL = "/v1/stats/summary";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private StatsService statsService;

    private StatsSummaryResponse sampleResponse(Long configId, Instant from, Instant to) {
        return new StatsSummaryResponse(
                configId,
                new TimeRangeResponse(from, to),
                1523,
                Map.of(RuleCategory.INJECTION, new CategoryStatsResponse(450, 72.3)),
                Map.of(Action.DENY, 890L),
                List.of(new AttackerStatsResponse("203.0.113.42", 87, 81.2)),
                List.of(new TargetedPathStatsResponse("/api/v1/login", 234)));
    }

    @Test
    void validRequestWithConfigIdReturns200() throws Exception {
        Instant from = Instant.parse("2026-07-01T00:00:00Z");
        Instant to = Instant.parse("2026-07-02T00:00:00Z");
        when(statsService.getSummary(14227L, from, to)).thenReturn(sampleResponse(14227L, from, to));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-02T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").value(14227))
                .andExpect(jsonPath("$.timeRange.from").value("2026-07-01T00:00:00Z"))
                .andExpect(jsonPath("$.timeRange.to").value("2026-07-02T00:00:00Z"))
                .andExpect(jsonPath("$.totalEvents").value(1523))
                .andExpect(jsonPath("$.byCategory.INJECTION.count").value(450))
                .andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(72.3))
                .andExpect(jsonPath("$.byAction.DENY").value(890))
                .andExpect(jsonPath("$.topAttackers[0].clientIp").value("203.0.113.42"))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/api/v1/login"));

        verify(statsService).getSummary(14227L, from, to);
    }

    @Test
    void validRequestWithoutConfigIdReturns200WithNullConfigId() throws Exception {
        Instant from = Instant.parse("2026-07-01T00:00:00Z");
        Instant to = Instant.parse("2026-07-02T00:00:00Z");
        when(statsService.getSummary(isNull(), eq(from), eq(to))).thenReturn(sampleResponse(null, from, to));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-02T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").doesNotExist());

        verify(statsService).getSummary(isNull(), eq(from), eq(to));
    }

    @Test
    void malformedFromReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "not-a-date")
                        .param("to", "2026-07-02T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'from')]").exists());

        verifyNoInteractions(statsService);
    }

    @Test
    void malformedToReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "not-a-date"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(statsService);
    }

    @Test
    void missingFromReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("to", "2026-07-02T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'from')]").exists());

        verifyNoInteractions(statsService);
    }

    @Test
    void missingToReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(statsService);
    }

    @Test
    void fromEqualToToReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(statsService);
    }

    @Test
    void fromAfterToReturns400() throws Exception {
        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", "2026-07-02T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(statsService);
    }
}
