package com.eitanroni.miniwsa.persistence.repository;

import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long> {
}
