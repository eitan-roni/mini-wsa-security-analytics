package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Writes a generated dataset as a UTF-8 JSON array, directly usable as the
 * request body for {@code POST /v1/events/ingest}. No Spring context is
 * started to do this, so the {@link ObjectMapper} is configured by hand to
 * match the behavior Spring Boot would otherwise auto-configure (ISO-8601
 * instants rather than numeric timestamps).
 */
public class EventJsonWriter {

    private final ObjectMapper objectMapper;

    public EventJsonWriter() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public void write(List<SecurityEventRequest> events, String outputPath) throws IOException {
        objectMapper.writeValue(new File(outputPath), events);
    }
}
