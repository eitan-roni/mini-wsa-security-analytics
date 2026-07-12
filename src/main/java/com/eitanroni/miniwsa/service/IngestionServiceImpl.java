package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.IngestedEventResult;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.mapper.SecurityEventEntityMapper;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
public class IngestionServiceImpl implements IngestionService {

    private static final String EVENT_ID_UNIQUE_CONSTRAINT = "uq_security_events_event_id";

    private final Clock clock;
    private final SecurityEventRepository repository;
    private final SecurityEventEntityMapper mapper;

    public IngestionServiceImpl(Clock clock, SecurityEventRepository repository, SecurityEventEntityMapper mapper) {
        this.clock = clock;
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public EventIngestionResponse ingest(List<SecurityEventRequest> events) {
        Instant receivedAt = Instant.now(clock);

        List<SecurityEventEntity> entities = events.stream()
                .map(event -> mapper.toEntity(event, receivedAt))
                .toList();

        try {
            repository.saveAllAndFlush(entities);
        } catch (DataIntegrityViolationException ex) {
            if (isDuplicateEventIdViolation(ex)) {
                throw new DuplicateEventException("One or more submitted event IDs already exist", ex);
            }
            throw ex;
        }

        List<IngestedEventResult> results = events.stream()
                .map(event -> new IngestedEventResult(event.eventId(), receivedAt))
                .toList();

        return new EventIngestionResponse(results.size(), results);
    }

    private boolean isDuplicateEventIdViolation(DataIntegrityViolationException ex) {
        return ex.getCause() instanceof ConstraintViolationException constraintViolation
                && EVENT_ID_UNIQUE_CONSTRAINT.equals(constraintViolation.getConstraintName());
    }
}
