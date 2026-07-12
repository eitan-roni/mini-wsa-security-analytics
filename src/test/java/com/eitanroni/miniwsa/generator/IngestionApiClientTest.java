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
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link IngestionApiClient} against a local JDK
 * {@link HttpServer} on an ephemeral port - no real network service is
 * involved.
 */
class IngestionApiClientTest {

    private HttpServer server;
    private final List<String> receivedPaths = Collections.synchronizedList(new ArrayList<>());
    private final List<String> receivedContentTypes = Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> receivedBatchSizes = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger requestCount = new AtomicInteger();
    private int failOnRequestNumber = -1;

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    private String startServer(String contextPath) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext(contextPath, this::handle);
        server.start();
        return "http://localhost:" + server.getAddress().getPort() + contextPath;
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        int requestNumber = requestCount.incrementAndGet();
        byte[] body = exchange.getRequestBody().readAllBytes();
        JsonNode batch = objectMapper.readTree(body);

        receivedPaths.add(exchange.getRequestURI().getPath());
        receivedContentTypes.add(exchange.getRequestHeaders().getFirst("Content-Type"));
        receivedBatchSizes.add(batch.size());

        int status;
        byte[] responseBody;
        if (requestNumber == failOnRequestNumber) {
            status = 500;
            responseBody = "{\"error\":\"INTERNAL_ERROR\"}".getBytes(StandardCharsets.UTF_8);
        } else {
            status = 201;
            responseBody = "{\"acceptedCount\":1}".getBytes(StandardCharsets.UTF_8);
        }

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, responseBody.length);
        try (OutputStream responseStream = exchange.getResponseBody()) {
            responseStream.write(responseBody);
        }
    }

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

    private List<SecurityEventRequest> events(int count) {
        List<SecurityEventRequest> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(sampleEvent("evt-" + i));
        }
        return events;
    }

    @Test
    void batchesUseConfiguredBatchSizeIncludingFinalPartialBatch() throws IOException {
        String apiUrl = startServer("/v1/events/ingest");
        IngestionApiClient client = new IngestionApiClient(objectMapper);

        SubmissionResult result = client.submit(events(25), apiUrl, 10, new PrintStream(new ByteArrayOutputStream()));

        assertThat(result.success()).isTrue();
        assertThat(result.totalBatches()).isEqualTo(3);
        assertThat(result.submittedEvents()).isEqualTo(25);
        assertThat(receivedBatchSizes).containsExactly(10, 10, 5);
    }

    @Test
    void correctEndpointAndContentTypeAreUsed() throws IOException {
        String apiUrl = startServer("/v1/events/ingest");
        IngestionApiClient client = new IngestionApiClient(objectMapper);

        client.submit(events(5), apiUrl, 10, new PrintStream(new ByteArrayOutputStream()));

        assertThat(receivedPaths).containsExactly("/v1/events/ingest");
        assertThat(receivedContentTypes).containsExactly("application/json");
    }

    @Test
    void nonTwoxxResponseStopsProcessingAndReportsFailure() throws IOException {
        String apiUrl = startServer("/v1/events/ingest");
        failOnRequestNumber = 2;
        IngestionApiClient client = new IngestionApiClient(objectMapper);

        SubmissionResult result = client.submit(events(30), apiUrl, 10, new PrintStream(new ByteArrayOutputStream()));

        assertThat(result.success()).isFalse();
        assertThat(result.failedBatchNumber()).isEqualTo(2);
        assertThat(result.submittedEvents()).isEqualTo(10);
        assertThat(result.failureMessage()).contains("500");
        assertThat(receivedBatchSizes).hasSize(2);
    }
}
