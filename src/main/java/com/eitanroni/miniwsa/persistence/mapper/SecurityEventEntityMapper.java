package com.eitanroni.miniwsa.persistence.mapper;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.service.enrichment.EnrichedSecurityEvent;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventEntityMapper {

    public SecurityEventEntity toEntity(EnrichedSecurityEvent enrichedEvent) {
        SecurityEventRequest request = enrichedEvent.original();

        return new SecurityEventEntity(
                request.eventId(),
                request.timestamp(),
                enrichedEvent.receivedAt(),
                request.configId(),
                request.policyId(),
                request.clientIp(),
                request.hostname(),
                request.path(),
                request.method(),
                request.statusCode(),
                request.userAgent(),
                request.rule().id(),
                request.rule().name(),
                request.rule().message(),
                request.rule().severity(),
                request.rule().category(),
                request.action(),
                request.geoLocation().country(),
                request.geoLocation().city(),
                request.requestSize(),
                request.responseSize(),
                enrichedEvent.attackType(),
                enrichedEvent.threatScore()
        );
    }
}
