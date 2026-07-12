package com.eitanroni.miniwsa.persistence.repository;

import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.repository.projection.ActionStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.CategoryStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.ClientIpStatsProjection;
import com.eitanroni.miniwsa.persistence.repository.projection.PathStatsProjection;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long>,
        JpaSpecificationExecutor<SecurityEventEntity> {

    long countByClientIpAndEventTimestampBetween(String clientIp, Instant windowStart, Instant windowEnd);

    @Query("""
            SELECT COUNT(e)
            FROM SecurityEventEntity e
            WHERE (:configId IS NULL OR e.configId = :configId)
              AND e.receivedAt >= :from AND e.receivedAt < :to
            """)
    long countByReceivedAtRange(@Param("configId") Long configId, @Param("from") Instant from, @Param("to") Instant to);

    @Query("""
            SELECT e.category AS category, COUNT(e) AS count, AVG(e.threatScore) AS avgThreatScore
            FROM SecurityEventEntity e
            WHERE (:configId IS NULL OR e.configId = :configId)
              AND e.receivedAt >= :from AND e.receivedAt < :to
            GROUP BY e.category
            """)
    List<CategoryStatsProjection> aggregateByCategory(@Param("configId") Long configId, @Param("from") Instant from, @Param("to") Instant to);

    @Query("""
            SELECT e.action AS action, COUNT(e) AS count
            FROM SecurityEventEntity e
            WHERE (:configId IS NULL OR e.configId = :configId)
              AND e.receivedAt >= :from AND e.receivedAt < :to
            GROUP BY e.action
            """)
    List<ActionStatsProjection> aggregateByAction(@Param("configId") Long configId, @Param("from") Instant from, @Param("to") Instant to);

    @Query("""
            SELECT e.clientIp AS clientIp, COUNT(e) AS count, AVG(e.threatScore) AS avgThreatScore
            FROM SecurityEventEntity e
            WHERE (:configId IS NULL OR e.configId = :configId)
              AND e.receivedAt >= :from AND e.receivedAt < :to
            GROUP BY e.clientIp
            ORDER BY COUNT(e) DESC, e.clientIp ASC
            """)
    List<ClientIpStatsProjection> findTopAttackers(@Param("configId") Long configId, @Param("from") Instant from, @Param("to") Instant to, Pageable pageable);

    @Query("""
            SELECT e.path AS path, COUNT(e) AS count
            FROM SecurityEventEntity e
            WHERE (:configId IS NULL OR e.configId = :configId)
              AND e.receivedAt >= :from AND e.receivedAt < :to
            GROUP BY e.path
            ORDER BY COUNT(e) DESC, e.path ASC
            """)
    List<PathStatsProjection> findTopTargetedPaths(@Param("configId") Long configId, @Param("from") Instant from, @Param("to") Instant to, Pageable pageable);
}
