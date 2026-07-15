package com.eitanroni.miniwsa.integration;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import com.eitanroni.miniwsa.persistence.entity.SecurityEventEntity;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class StatsPostgresIntegrationTest {

    private static final String SUMMARY_URL = "/v1/stats/summary";
    private static final Instant WINDOW_FROM = Instant.parse("2026-07-01T00:00:00Z");
    private static final Instant WINDOW_TO = Instant.parse("2026-07-02T00:00:00Z");

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityEventRepository repository;

    private final AtomicInteger eventIdSequence = new AtomicInteger();

    @BeforeEach
    void cleanDatabase() {
        repository.deleteAll();
    }

    private SecurityEventEntity event(Long configId, Instant eventTimestamp, Instant receivedAt,
                                       String clientIp, String path, RuleCategory category,
                                       Action action, int threatScore) {
        return new SecurityEventEntity(
                "evt-" + eventIdSequence.incrementAndGet(),
                eventTimestamp,
                receivedAt,
                configId,
                "policy-1",
                clientIp,
                "example.com",
                path,
                "POST",
                403,
                "Mozilla/5.0",
                "950001",
                "SOME_RULE",
                "Some rule message",
                Severity.HIGH,
                category,
                action,
                "US",
                "San Francisco",
                512L,
                0L,
                "Attack Type",
                threatScore);
    }

    private void seed(SecurityEventEntity... events) {
        repository.saveAll(List.of(events));
    }

    // verify that stats are calculated by receivedAt (and not by eventTimestamp )
    @Test
    void filtersByReceivedAtNotEventTimestamp() throws Exception {
        seed(
                // event timestamp outside the window, but receivedAt inside it: must be included
                event(14227L, Instant.parse("2026-06-01T00:00:00Z"), Instant.parse("2026-07-01T12:00:00Z"),
                        "203.0.113.1", "/included", RuleCategory.INJECTION, Action.DENY, 50),
                // event timestamp inside the window, but receivedAt outside it: must be excluded
                event(14227L, Instant.parse("2026-07-01T12:00:00Z"), Instant.parse("2026-06-01T00:00:00Z"),
                        "203.0.113.2", "/excluded", RuleCategory.INJECTION, Action.DENY, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(1))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/included"));
    }

    @Test
    void includesEventExactlyAtFrom() throws Exception {
        seed(event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/at-from",
                RuleCategory.INJECTION, Action.DENY, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(1));
    }

    @Test
    void excludesEventExactlyAtTo() throws Exception {
        seed(event(14227L, WINDOW_TO, WINDOW_TO, "203.0.113.1", "/at-to",
                RuleCategory.INJECTION, Action.DENY, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(0));
    }

    @Test
    void filtersByConfigIdWhenSupplied() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/config-a",
                        RuleCategory.INJECTION, Action.DENY, 50),
                event(99999L, WINDOW_FROM, WINDOW_FROM, "203.0.113.2", "/config-b",
                        RuleCategory.INJECTION, Action.DENY, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(1))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/config-a"));
    }

    // saving events from two difference configurations
    @Test
    void aggregatesAcrossConfigurationsWhenConfigIdAbsent() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/config-a",
                        RuleCategory.INJECTION, Action.DENY, 50),
                event(99999L, WINDOW_FROM, WINDOW_FROM, "203.0.113.2", "/config-b",
                        RuleCategory.INJECTION, Action.DENY, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.configId").doesNotExist())
                .andExpect(jsonPath("$.totalEvents").value(2));
    }

    // varify that average , count and group by are successfully calculated by PostgreSQL
    @Test
    void correctCategoryCountsAndAverageScores() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/p1", RuleCategory.INJECTION, Action.DENY, 60),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.2", "/p2", RuleCategory.INJECTION, Action.DENY, 70),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.3", "/p3", RuleCategory.INJECTION, Action.DENY, 80),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.4", "/p4", RuleCategory.XSS, Action.ALERT, 50),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.5", "/p5", RuleCategory.XSS, Action.ALERT, 60));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.byCategory.INJECTION.count").value(3))
                .andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(70.0))
                .andExpect(jsonPath("$.byCategory.XSS.count").value(2))
                .andExpect(jsonPath("$.byCategory.XSS.avgThreatScore").value(55.0));
    }

    @Test
    void correctActionCounts() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/p1", RuleCategory.INJECTION, Action.DENY, 50),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.2", "/p2", RuleCategory.INJECTION, Action.DENY, 50),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.3", "/p3", RuleCategory.BOT, Action.ALERT, 50),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.4", "/p4", RuleCategory.BOT, Action.MONITOR, 50));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.byAction.DENY").value(2))
                .andExpect(jsonPath("$.byAction.ALERT").value(1))
                .andExpect(jsonPath("$.byAction.MONITOR").value(1));
    }

    // group by IPS and sort by count
    @Test
    void topAttackersOrderedByCountAndLimitedToTen() throws Exception {
        List<SecurityEventEntity> events = new ArrayList<>();
        // 11 distinct clientIps, ip-1 has 11 matching events down to ip-11 with 1
        for (int clientIndex = 1; clientIndex <= 11; clientIndex++) {
            int occurrences = 12 - clientIndex;
            for (int i = 0; i < occurrences; i++) {
                events.add(event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113." + clientIndex,
                        "/path", RuleCategory.INJECTION, Action.DENY, 50));
            }
        }
        seed(events.toArray(new SecurityEventEntity[0]));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.topAttackers.length()").value(10))
                .andExpect(jsonPath("$.topAttackers[0].clientIp").value("203.0.113.1"))
                .andExpect(jsonPath("$.topAttackers[0].count").value(11))
                .andExpect(jsonPath("$.topAttackers[9].clientIp").value("203.0.113.10"))
                .andExpect(jsonPath("$.topAttackers[9].count").value(2));
    }

    @Test
    void topTargetedPathsOrderedByCountAndLimitedToTen() throws Exception {
        List<SecurityEventEntity> events = new ArrayList<>();
        // 11 distinct paths, path-1 has 11 matching events down to path-11 with 1
        for (int pathIndex = 1; pathIndex <= 11; pathIndex++) {
            int occurrences = 12 - pathIndex;
            for (int i = 0; i < occurrences; i++) {
                events.add(event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1",
                        "/path-" + pathIndex, RuleCategory.INJECTION, Action.DENY, 50));
            }
        }
        seed(events.toArray(new SecurityEventEntity[0]));

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.topTargetedPaths.length()").value(10))
                .andExpect(jsonPath("$.topTargetedPaths[0].path").value("/path-1"))
                .andExpect(jsonPath("$.topTargetedPaths[0].count").value(11))
                .andExpect(jsonPath("$.topTargetedPaths[9].path").value("/path-10"))
                .andExpect(jsonPath("$.topTargetedPaths[9].count").value(2));
    }

    // no events in range of time
    @Test
    void emptyTimeRangeResultReturnsEmptyAggregates() throws Exception {
        seed(event(14227L, WINDOW_FROM, WINDOW_FROM, "203.0.113.1", "/p1",
                RuleCategory.INJECTION, Action.DENY, 50));

        Instant emptyFrom = Instant.parse("2030-01-01T00:00:00Z");
        Instant emptyTo = Instant.parse("2030-01-02T00:00:00Z");

        mockMvc.perform(get(SUMMARY_URL)
                        .param("configId", "14227")
                        .param("from", emptyFrom.toString())
                        .param("to", emptyTo.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(0))
                .andExpect(jsonPath("$.byCategory").isEmpty())
                .andExpect(jsonPath("$.byAction").isEmpty())
                .andExpect(jsonPath("$.topAttackers").isEmpty())
                .andExpect(jsonPath("$.topTargetedPaths").isEmpty());
    }
}
