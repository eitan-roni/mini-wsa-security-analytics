package com.eitanroni.miniwsa.persistence.repository;

import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long> {

    long countByClientIpAndEventTimestampBetween(String clientIp, Instant windowStart, Instant windowEnd);
}
