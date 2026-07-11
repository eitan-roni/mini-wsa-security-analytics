package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.IngestedEventResult;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
public class IngestionServiceImpl implements IngestionService {

    private final Clock clock;

    public IngestionServiceImpl(Clock clock) {
        this.clock = clock;
    }

    @Override
    public EventIngestionResponse ingest(List<SecurityEventRequest> events) {
        Instant receivedAt = Instant.now(clock);

        List<IngestedEventResult> results = events.stream()
                .map(event -> new IngestedEventResult(event.eventId(), receivedAt))
                .toList();

        return new EventIngestionResponse(results.size(), results);
    }
}
