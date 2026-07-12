package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.GeoLocationResponse;
import com.eitanroni.miniwsa.api.dto.RuleResponse;
import com.eitanroni.miniwsa.api.dto.SampleEventResponse;
import com.eitanroni.miniwsa.api.dto.SampleSearchResponse;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import com.eitanroni.miniwsa.persistence.repository.support.OffsetBasedPageable;
import com.eitanroni.miniwsa.persistence.repository.support.SecurityEventSpecifications;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class SamplesServiceImpl implements SamplesService {

    private static final Sort SORT = Sort.by(Sort.Order.desc("eventTimestamp"), Sort.Order.desc("id"));

    private final SecurityEventRepository repository;

    public SamplesServiceImpl(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(readOnly = true)
    public SampleSearchResponse search(SampleSearchCriteria criteria) {
        Specification<SecurityEventEntity> spec = Specification
                .where(SecurityEventSpecifications.configIdEquals(criteria.configId()))
                .and(SecurityEventSpecifications.eventTimestampFrom(criteria.from()))
                .and(SecurityEventSpecifications.eventTimestampTo(criteria.to()))
                .and(SecurityEventSpecifications.categoryEquals(criteria.category()))
                .and(SecurityEventSpecifications.actionEquals(criteria.action()));

        Pageable pageable = new OffsetBasedPageable(criteria.offset(), criteria.limit(), SORT);

        Page<SecurityEventEntity> page = repository.findAll(spec, pageable);

        List<SampleEventResponse> events = page.getContent().stream()
                .map(this::toResponse)
                .toList();

        return new SampleSearchResponse(page.getTotalElements(), criteria.limit(), criteria.offset(), events);
    }

    private SampleEventResponse toResponse(SecurityEventEntity entity) {
        return new SampleEventResponse(
                entity.getEventId(),
                entity.getEventTimestamp(),
                entity.getConfigId(),
                entity.getPolicyId(),
                entity.getClientIp(),
                entity.getHostname(),
                entity.getPath(),
                entity.getHttpMethod(),
                entity.getStatusCode(),
                entity.getUserAgent(),
                new RuleResponse(entity.getRuleId(), entity.getRuleName(), entity.getRuleMessage(),
                        entity.getSeverity(), entity.getCategory()),
                entity.getAction(),
                new GeoLocationResponse(entity.getCountry(), entity.getCity()),
                entity.getRequestSize(),
                entity.getResponseSize(),
                entity.getReceivedAt(),
                entity.getAttackType(),
                entity.getThreatScore());
    }
}
