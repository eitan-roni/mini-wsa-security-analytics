package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EventJsonWriterTest {

    @TempDir
    Path tempDir;

    private SecurityEventRequest sampleEvent(String eventId) {
        return new SecurityEventRequest(
                eventId,
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION),
                Action.DENY,
                new GeoLocationRequest("US", "San Francisco"),
                512L,
                0L);
    }

    @Test
    void writesValidJsonArrayThatDeserializesBackToTheSameRequestDtos() throws IOException {
        List<SecurityEventRequest> events = List.of(sampleEvent("evt-1"), sampleEvent("evt-2"), sampleEvent("evt-3"));
        Path outputFile = tempDir.resolve("events.json");

        new EventJsonWriter().write(events, outputFile.toString());

        assertThat(Files.exists(outputFile)).isTrue();

        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        JsonNode root = mapper.readTree(outputFile.toFile());
        assertThat(root.isArray()).isTrue();
        assertThat(root.size()).isEqualTo(3);

        List<SecurityEventRequest> roundTripped = mapper.readValue(outputFile.toFile(),
                mapper.getTypeFactory().constructCollectionType(List.class, SecurityEventRequest.class));

        assertThat(roundTripped).isEqualTo(events);
    }

    @Test
    void writesEmptyArrayForEmptyDataset() throws IOException {
        Path outputFile = tempDir.resolve("empty.json");

        new EventJsonWriter().write(List.of(), outputFile.toString());

        JsonNode root = new ObjectMapper().readTree(outputFile.toFile());
        assertThat(root.isArray()).isTrue();
        assertThat(root.size()).isZero();
    }
}
