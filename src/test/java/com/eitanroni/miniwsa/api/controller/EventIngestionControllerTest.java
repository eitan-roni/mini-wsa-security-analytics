package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.IngestedEventResult;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.service.IngestionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(EventIngestionController.class)
class EventIngestionControllerTest {

    private static final String INGEST_URL = "/v1/events/ingest";

    private static final Instant FIXED_INSTANT =
            Instant.parse("2026-07-11T12:00:00Z");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private IngestionService ingestionService;

    private ObjectNode validEventNode(String eventId) {
        ObjectNode rule = objectMapper.createObjectNode()
                .put("id", "950001")
                .put("name", "SQL_INJECTION")
                .put("message", "SQL Injection Attack Detected")
                .put("severity", "CRITICAL")
                .put("category", "INJECTION");

        ObjectNode geoLocation = objectMapper.createObjectNode()
                .put("country", "US")
                .put("city", "San Francisco");

        ObjectNode event = objectMapper.createObjectNode();
        event.put("eventId", eventId);
        event.put("timestamp", "2026-07-11T10:15:30Z");
        event.put("configId", 14227);
        event.put("policyId", "policy-1");
        event.put("clientIp", "203.0.113.10");
        event.put("hostname", "example.com");
        event.put("path", "/login");
        event.put("method", "POST");
        event.put("statusCode", 403);
        event.put("userAgent", "Mozilla/5.0");
        event.set("rule", rule);
        event.put("action", "DENY");
        event.set("geoLocation", geoLocation);
        event.put("requestSize", 512);
        event.put("responseSize", 0);
        return event;
    }

    @Test
    void validSingleEventReturns201() throws Exception {
        when(ingestionService.ingest(anyList())).thenReturn(
                new EventIngestionResponse(1, List.of(new IngestedEventResult("evt-1", FIXED_INSTANT ))));

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-1"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.acceptedCount").value(1))
                .andExpect(jsonPath("$.events.length()").value(1))
                .andExpect(jsonPath("$.events[0].eventId").value("evt-1"))
                .andExpect(jsonPath("$.events[0].receivedAt").value("2026-07-11T12:00:00Z"));
    }

    @Test
    void validBatchReturns201() throws Exception {
        when(ingestionService.ingest(anyList())).thenReturn(
                new EventIngestionResponse(3, List.of(
                        new IngestedEventResult("evt-1", FIXED_INSTANT ),
                        new IngestedEventResult("evt-2", FIXED_INSTANT ),
                        new IngestedEventResult("evt-3", FIXED_INSTANT ))));

        ArrayNode batch = objectMapper.createArrayNode();
        batch.add(validEventNode("evt-1"));
        batch.add(validEventNode("evt-2"));
        batch.add(validEventNode("evt-3"));

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(batch)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.acceptedCount").value(3))
                .andExpect(jsonPath("$.events.length()").value(3))
                .andExpect(jsonPath("$.events[0].eventId").value("evt-1"))
                .andExpect(jsonPath("$.events[1].eventId").value("evt-2"))
                .andExpect(jsonPath("$.events[2].eventId").value("evt-3"))
                .andExpect(jsonPath("$.events[0].receivedAt").value("2026-07-11T12:00:00Z"))
                .andExpect(jsonPath("$.events[1].receivedAt").value("2026-07-11T12:00:00Z"))
                .andExpect(jsonPath("$.events[2].receivedAt").value("2026-07-11T12:00:00Z"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void serviceReceivesOneEventForSingleObjectRequest() throws Exception {
        when(ingestionService.ingest(anyList())).thenReturn(
                new EventIngestionResponse(
                        1,
                        List.of(new IngestedEventResult("evt-1", FIXED_INSTANT))
                )
        );

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-1"))))
                .andExpect(status().isCreated());

        ArgumentCaptor<List<SecurityEventRequest>> captor =
                ArgumentCaptor.forClass(List.class);

        verify(ingestionService).ingest(captor.capture());

        assertThat(captor.getValue()).hasSize(1);

        SecurityEventRequest capturedEvent = captor.getValue().get(0);

        assertThat(capturedEvent.eventId()).isEqualTo("evt-1");
        assertThat(capturedEvent.configId()).isEqualTo(14227L);
        assertThat(capturedEvent.policyId()).isEqualTo("policy-1");
        assertThat(capturedEvent.clientIp()).isEqualTo("203.0.113.10");
        assertThat(capturedEvent.path()).isEqualTo("/login");
        assertThat(capturedEvent.action()).isEqualTo(Action.DENY);

        assertThat(capturedEvent.rule().id()).isEqualTo("950001");
        assertThat(capturedEvent.rule().name()).isEqualTo("SQL_INJECTION");
        assertThat(capturedEvent.rule().message())
                .isEqualTo("SQL Injection Attack Detected");
        assertThat(capturedEvent.rule().severity()).isEqualTo(Severity.CRITICAL);
        assertThat(capturedEvent.rule().category()).isEqualTo(RuleCategory.INJECTION);
    }

    @Test
    @SuppressWarnings("unchecked")
    void serviceReceivesAllEventsForBatchRequest() throws Exception {
        when(ingestionService.ingest(anyList())).thenReturn(
                new EventIngestionResponse(
                        3,
                        List.of(
                                new IngestedEventResult("evt-1", FIXED_INSTANT),
                                new IngestedEventResult("evt-2", FIXED_INSTANT),
                                new IngestedEventResult("evt-3", FIXED_INSTANT)
                        )
                )
        );

        ArrayNode batch = objectMapper.createArrayNode();
        batch.add(validEventNode("evt-1"));
        batch.add(validEventNode("evt-2"));
        batch.add(validEventNode("evt-3"));

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(batch)))
                .andExpect(status().isCreated());

        ArgumentCaptor<List<SecurityEventRequest>> captor =
                ArgumentCaptor.forClass(List.class);

        verify(ingestionService).ingest(captor.capture());

        assertThat(captor.getValue())
                .extracting(SecurityEventRequest::eventId)
                .containsExactly("evt-1", "evt-2", "evt-3");

        assertThat(captor.getValue())
                .extracting(SecurityEventRequest::configId)
                .containsOnly(14227L);
    }

    @Test
    void missingRequiredTopLevelFieldReturns400() throws Exception {
        ObjectNode event = validEventNode("evt-1");
        event.remove("eventId");

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(event)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.violations[?(@.field == 'events[0].eventId')]").exists());

        verifyNoInteractions(ingestionService);
    }

    @Test
    void invalidNestedRuleFieldReturns400() throws Exception {
        ObjectNode event = validEventNode("evt-1");
        ((ObjectNode) event.get("rule")).put("id", "");

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(event)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'events[0].rule.id')]").exists());

        verifyNoInteractions(ingestionService);
    }

    @Test
    void invalidEventInsideBatchReturns400WithIndex() throws Exception {
        ObjectNode validEvent = validEventNode("evt-1");
        ObjectNode invalidEvent = validEventNode("evt-2");
        ((ObjectNode) invalidEvent.get("rule")).put("id", "");

        ArrayNode batch = objectMapper.createArrayNode();
        batch.add(validEvent);
        batch.add(invalidEvent);

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(batch)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'events[1].rule.id')]").exists());

        verifyNoInteractions(ingestionService);
    }

    @Test
    void negativeRequestSizeReturns400() throws Exception {
        ObjectNode event = validEventNode("evt-1");
        event.put("requestSize", -1);

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(event)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'events[0].requestSize')]").exists());

        verifyNoInteractions(ingestionService);
    }

    @Test
    void invalidEnumValueReturns400() throws Exception {
        ObjectNode event = validEventNode("evt-1");
        event.put("action", "NOT_A_REAL_ACTION");

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(event)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST_BODY"));

        verifyNoInteractions(ingestionService);
    }

    @Test
    void invalidTimestampFormatReturns400() throws Exception {
        ObjectNode event = validEventNode("evt-1");
        event.put("timestamp", "not-a-date");

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(event)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST_BODY"));

        verifyNoInteractions(ingestionService);
    }

    @Test
    void emptyArrayReturns400() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("[]"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.violations[?(@.field == 'events')]").exists());

        verifyNoInteractions(ingestionService);
    }

    @Test
    void malformedJsonReturns400() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ this is not valid json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST_BODY"));

        verifyNoInteractions(ingestionService);
    }

    @Test
    void jsonPrimitiveRootReturns400() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("\"just a string\""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST_BODY"));

        verifyNoInteractions(ingestionService);
    }
}
