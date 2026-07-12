package com.eitanroni.miniwsa.integration;

import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class EventIngestionPostgresIntegrationTest {

    private static final String INGEST_URL = "/v1/events/ingest";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityEventRepository repository;

    @BeforeEach
    void cleanDatabase() {
        repository.deleteAll();
    }

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
    void flywayMigrationAndHibernateValidationSucceed() {
        assertThat(repository.count()).isZero();
    }

    @Test
    void singleValidEventReturns201AndInsertsOneRow() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-1"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.acceptedCount").value(1));

        assertThat(repository.count()).isEqualTo(1);
        assertThat(repository.findAll())
                .extracting(SecurityEventEntity::getEventId)
                .containsExactly("evt-1");
    }

    @Test
    void validBatchReturns201AndInsertsEveryEvent() throws Exception {
        ArrayNode batch = objectMapper.createArrayNode();
        batch.add(validEventNode("evt-1"));
        batch.add(validEventNode("evt-2"));
        batch.add(validEventNode("evt-3"));

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(batch)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.acceptedCount").value(3));

        assertThat(repository.count()).isEqualTo(3);
    }

    @Test
    void duplicateEventIdReturns409() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-dup"))))
                .andExpect(status().isCreated());

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-dup"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("DUPLICATE_EVENT"));

        assertThat(repository.count()).isEqualTo(1);
    }

    @Test
    void batchContainingDuplicateRollsBackCompletely() throws Exception {
        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validEventNode("evt-existing"))))
                .andExpect(status().isCreated());

        ArrayNode batch = objectMapper.createArrayNode();
        batch.add(validEventNode("evt-new"));
        batch.add(validEventNode("evt-existing"));

        mockMvc.perform(post(INGEST_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(batch)))
                .andExpect(status().isConflict());

        assertThat(repository.count()).isEqualTo(1);
        assertThat(repository.findAll())
                .extracting(SecurityEventEntity::getEventId)
                .containsExactly("evt-existing");
    }
}
