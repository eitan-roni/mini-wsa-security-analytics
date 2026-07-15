package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.GeoLocationResponse;
import com.eitanroni.miniwsa.api.dto.RuleResponse;
import com.eitanroni.miniwsa.api.dto.SampleEventResponse;
import com.eitanroni.miniwsa.api.dto.SampleSearchResponse;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.service.SampleSearchCriteria;
import com.eitanroni.miniwsa.service.SamplesService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SamplesController.class)
class SamplesControllerTest {

    private static final String SAMPLES_URL = "/v1/events/samples";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SamplesService samplesService;

    private SampleSearchResponse emptyResponse(int limit, int offset) {
        return new SampleSearchResponse(0, limit, offset, List.of());
    }

    private SampleSearchResponse sampleResponse(int limit, int offset) {
        SampleEventResponse event = new SampleEventResponse(
                "evt-1",
                Instant.parse("2026-07-01T10:00:00Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                new RuleResponse("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION),
                Action.DENY,
                new GeoLocationResponse("US", "San Francisco"),
                512L,
                0L,
                Instant.parse("2026-07-01T10:00:01Z"),
                "SQL/Command Injection",
                75);
        return new SampleSearchResponse(1, limit, offset, List.of(event));
    }

    // a query without parameters, use default params (limit = 20 , offset = 0)
    @Test
    void noQueryParametersUsesLimitTwentyAndOffsetZero() throws Exception {
        when(samplesService.search(any())).thenReturn(emptyResponse(20, 0));

        mockMvc.perform(get(SAMPLES_URL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.limit").value(20))
                .andExpect(jsonPath("$.offset").value(0));

        // Catch the SampleSearchCriteria who the controller sent to the service
        var captor = ArgumentCaptor.forClass(SampleSearchCriteria.class);
        verify(samplesService).search(captor.capture());

        SampleSearchCriteria criteria = captor.getValue();
        assertThat(criteria.configId()).isNull();
        assertThat(criteria.from()).isNull();
        assertThat(criteria.to()).isNull();
        assertThat(criteria.category()).isNull();
        assertThat(criteria.action()).isNull();
        assertThat(criteria.limit()).isEqualTo(20);
        assertThat(criteria.offset()).isEqualTo(0);
    }

    // happy path test
    @Test
    void requestWithEveryFilterReturns200() throws Exception {
        when(samplesService.search(any())).thenReturn(sampleResponse(10, 5));

        mockMvc.perform(get(SAMPLES_URL)
                        .param("configId", "14227")
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-02T00:00:00Z")
                        .param("category", "INJECTION")
                        .param("action", "DENY")
                        .param("limit", "10")
                        .param("offset", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.limit").value(10))
                .andExpect(jsonPath("$.offset").value(5))
                .andExpect(jsonPath("$.events[0].eventId").value("evt-1"))
                .andExpect(jsonPath("$.events[0].rule.category").value("INJECTION"))
                .andExpect(jsonPath("$.events[0].geoLocation.country").value("US"))
                .andExpect(jsonPath("$.events[0].receivedAt").exists())
                .andExpect(jsonPath("$.events[0].attackType").value("SQL/Command Injection"))
                .andExpect(jsonPath("$.events[0].threatScore").value(75));

        var captor = ArgumentCaptor.forClass(SampleSearchCriteria.class);
        verify(samplesService).search(captor.capture());

        SampleSearchCriteria criteria = captor.getValue();
        assertThat(criteria.configId()).isEqualTo(14227L);
        assertThat(criteria.from()).isEqualTo(Instant.parse("2026-07-01T00:00:00Z"));
        assertThat(criteria.to()).isEqualTo(Instant.parse("2026-07-02T00:00:00Z"));
        assertThat(criteria.category()).isEqualTo(RuleCategory.INJECTION);
        assertThat(criteria.action()).isEqualTo(Action.DENY);
        assertThat(criteria.limit()).isEqualTo(10);
        assertThat(criteria.offset()).isEqualTo(5);
    }

    @Test
    void onlyFromIsAppliedAsLowerBoundOnly() throws Exception {
        when(samplesService.search(any())).thenReturn(emptyResponse(20, 0));

        mockMvc.perform(get(SAMPLES_URL).param("from", "2026-07-01T00:00:00Z"))
                .andExpect(status().isOk());

        var captor = ArgumentCaptor.forClass(SampleSearchCriteria.class);
        verify(samplesService).search(captor.capture());

        assertThat(captor.getValue().from()).isEqualTo(Instant.parse("2026-07-01T00:00:00Z"));
        assertThat(captor.getValue().to()).isNull();
    }

    @Test
    void onlyToIsAppliedAsUpperBoundOnly() throws Exception {
        when(samplesService.search(any())).thenReturn(emptyResponse(20, 0));

        mockMvc.perform(get(SAMPLES_URL).param("to", "2026-07-02T00:00:00Z"))
                .andExpect(status().isOk());

        var captor = ArgumentCaptor.forClass(SampleSearchCriteria.class);
        verify(samplesService).search(captor.capture());

        assertThat(captor.getValue().to()).isEqualTo(Instant.parse("2026-07-02T00:00:00Z"));
        assertThat(captor.getValue().from()).isNull();
    }

    // from timestamp unsupported (not ISO-8601)
    @Test
    void malformedFromReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("from", "not-a-date"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'from')]").exists());

        verifyNoInteractions(samplesService);
    }

    // to timestamp unsupported (not ISO-8601)
    @Test
    void malformedToReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("to", "not-a-date"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(samplesService);
    }

    // invalid enum params
    @Test
    void invalidCategoryReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("category", "NOT_A_CATEGORY"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'category')]").exists());

        verifyNoInteractions(samplesService);
    }

    // invalid enum param
    @Test
    void invalidActionReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("action", "NOT_AN_ACTION"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'action')]").exists());

        verifyNoInteractions(samplesService);
    }

    // limit = 0
    @Test
    void limitZeroReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("limit", "0"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'limit')]").exists());

        verifyNoInteractions(samplesService);
    }

    // limit > 100
    @Test
    void limitAboveMaximumReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("limit", "101"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'limit')]").exists());

        verifyNoInteractions(samplesService);
    }

    // negative offset
    @Test
    void negativeOffsetReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL).param("offset", "-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'offset')]").exists());

        verifyNoInteractions(samplesService);
    }

    // sends equal from / to
    @Test
    void fromEqualToToReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL)
                        .param("from", "2026-07-01T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        // the request don't move to the service
        verifyNoInteractions(samplesService);
    }

    // to < from
    @Test
    void fromAfterToReturns400() throws Exception {
        mockMvc.perform(get(SAMPLES_URL)
                        .param("from", "2026-07-02T00:00:00Z")
                        .param("to", "2026-07-01T00:00:00Z"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'to')]").exists());

        verifyNoInteractions(samplesService);
    }
}
