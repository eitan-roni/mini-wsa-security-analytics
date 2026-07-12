package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Submits a generated dataset to {@code POST /v1/events/ingest} in batches
 * using the JDK's built-in {@link HttpClient} (no HTTP client dependency
 * needed). Batches are sent strictly in order; the first non-2xx response or
 * transport failure stops submission immediately. There is no automatic
 * retry, so a failed batch must be resubmitted manually if desired.
 */
public class IngestionApiClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public IngestionApiClient(ObjectMapper objectMapper) {
        this(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build(), objectMapper);
    }

    public IngestionApiClient(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    public SubmissionResult submit(List<SecurityEventRequest> events, String apiUrl, int batchSize, PrintStream out) {
        int totalBatches = (events.size() + batchSize - 1) / batchSize;
        int submitted = 0;

        for (int batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
            int fromIndex = batchIndex * batchSize;
            int toIndex = Math.min(fromIndex + batchSize, events.size());
            List<SecurityEventRequest> batch = events.subList(fromIndex, toIndex);
            int batchNumber = batchIndex + 1;

            try {
                HttpResponse<String> response = sendBatch(batch, apiUrl);
                if (!isSuccess(response.statusCode())) {
                    return SubmissionResult.failure(batchNumber, totalBatches, submitted,
                            "HTTP " + response.statusCode() + ": " + response.body());
                }
                submitted += batch.size();
                out.printf("Submitted batch %d/%d: %d events%n", batchNumber, totalBatches, batch.size());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return SubmissionResult.failure(batchNumber, totalBatches, submitted,
                        "Request interrupted: " + ex.getMessage());
            } catch (IOException ex) {
                return SubmissionResult.failure(batchNumber, totalBatches, submitted,
                        "Request failed: " + ex.getMessage());
            }
        }

        return SubmissionResult.success(totalBatches, submitted);
    }

    private HttpResponse<String> sendBatch(List<SecurityEventRequest> batch, String apiUrl)
            throws IOException, InterruptedException {
        byte[] body = objectMapper.writeValueAsBytes(batch);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private boolean isSuccess(int statusCode) {
        return statusCode >= 200 && statusCode < 300;
    }
}
