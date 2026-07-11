package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.api.jackson.EventIngestionRequestDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

@JsonDeserialize(using = EventIngestionRequestDeserializer.class)
public record EventIngestionRequest(

        @NotEmpty
        @Valid
        List<SecurityEventRequest> events
) {
    public EventIngestionRequest {
        events = events == null ? List.of() : List.copyOf(events);
    }
}
