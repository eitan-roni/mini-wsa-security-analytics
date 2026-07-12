package com.eitanroni.miniwsa.generator;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityEventGeneratorMainTest {

    @TempDir
    Path tempDir;

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String startServerRespondingWith(int status, String body) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/v1/events/ingest", exchange -> {
            byte[] responseBody = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, responseBody.length);
            try (OutputStream responseStream = exchange.getResponseBody()) {
                responseStream.write(responseBody);
            }
        });
        server.start();
        return "http://localhost:" + server.getAddress().getPort() + "/v1/events/ingest";
    }

    @Test
    void helpFlagPrintsUsageAndExitsZeroWithoutGenerating() {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

        int exitCode = SecurityEventGeneratorMain.run(new String[]{"--help"},
                new PrintStream(outBytes), new PrintStream(errBytes));

        assertThat(exitCode).isEqualTo(0);
        assertThat(outBytes.toString(StandardCharsets.UTF_8)).contains("Usage:");
    }

    @Test
    void invalidArgumentsExitNonZeroAndCreateNoOutputFile() {
        Path outputFile = tempDir.resolve("should-not-exist.json");
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

        int exitCode = SecurityEventGeneratorMain.run(
                new String[]{"--count", "0", "--output", outputFile.toString()},
                new PrintStream(outBytes), new PrintStream(errBytes));

        assertThat(exitCode).isNotEqualTo(0);
        assertThat(errBytes.toString(StandardCharsets.UTF_8)).contains("Error:", "Usage:");
        assertThat(Files.exists(outputFile)).isFalse();
    }

    @Test
    void validRunGeneratesFileAndPrintsSummary() {
        Path outputFile = tempDir.resolve("events.json");
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

        int exitCode = SecurityEventGeneratorMain.run(
                new String[]{"--count", "50", "--seed", "7", "--output", outputFile.toString()},
                new PrintStream(outBytes), new PrintStream(errBytes));

        assertThat(exitCode).isEqualTo(0);
        assertThat(Files.exists(outputFile)).isTrue();

        String output = outBytes.toString(StandardCharsets.UTF_8);
        assertThat(output).contains("Generated 50 events", "Seed: 7", "Output: " + outputFile);
    }

    @Test
    void directSubmissionSuccessReportsSubmittedTotal() throws IOException {
        String apiUrl = startServerRespondingWith(201, "{\"acceptedCount\":1}");

        Path outputFile = tempDir.resolve("submitted.json");
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

        int exitCode = SecurityEventGeneratorMain.run(
                new String[]{"--count", "25", "--seed", "3", "--output", outputFile.toString(),
                        "--api-url", apiUrl, "--batch-size", "10"},
                new PrintStream(outBytes), new PrintStream(errBytes));

        assertThat(exitCode).isEqualTo(0);
        assertThat(outBytes.toString(StandardCharsets.UTF_8)).contains("Submitted 25 events successfully");
    }

    @Test
    void directSubmissionFailureExitsNonZeroAndReportsFailedBatch() throws IOException {
        String apiUrl = startServerRespondingWith(500, "{\"error\":\"INTERNAL_ERROR\"}");

        Path outputFile = tempDir.resolve("failed-submit.json");
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

        int exitCode = SecurityEventGeneratorMain.run(
                new String[]{"--count", "10", "--seed", "9", "--output", outputFile.toString(),
                        "--api-url", apiUrl, "--batch-size", "10"},
                new PrintStream(outBytes), new PrintStream(errBytes));

        assertThat(exitCode).isNotEqualTo(0);
        assertThat(Files.exists(outputFile)).isTrue();
        assertThat(errBytes.toString(StandardCharsets.UTF_8)).contains("batch 1", "500");
    }
}
