package com.eitanroni.miniwsa.persistence.mapper;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class SecurityEventEntityMapper {

    public SecurityEventEntity toEntity(SecurityEventRequest request, Instant receivedAt) {
        return new SecurityEventEntity(
                request.eventId(),
                request.timestamp(),
                receivedAt,
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
                request.responseSize()
        );
    }
}
