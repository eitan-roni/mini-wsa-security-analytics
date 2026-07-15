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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class SamplesPostgresIntegrationTest {

    private static final String SAMPLES_URL = "/v1/events/samples";
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
                                       String path, RuleCategory category, Action action) {
        return new SecurityEventEntity(
                "evt-" + eventIdSequence.incrementAndGet(),
                eventTimestamp,
                receivedAt,
                configId,
                "policy-1",
                "203.0.113.10",
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
                50);
    }

    private void seed(SecurityEventEntity... events) {
        repository.saveAll(List.of(events));
    }

    @Test
    void filtersByConfigIdInPostgres() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/config-a", RuleCategory.INJECTION, Action.DENY),
                event(99999L, WINDOW_FROM, WINDOW_FROM, "/config-b", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL).param("configId", "14227"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/config-a"));
    }

    @Test
    void filtersByFromOnlyInPostgres() throws Exception {
        seed(
                event(14227L, WINDOW_FROM.minus(1, ChronoUnit.DAYS), WINDOW_FROM, "/before", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/at-from", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM.plus(1, ChronoUnit.DAYS), WINDOW_FROM, "/after", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL).param("from", WINDOW_FROM.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(2));
    }

    @Test
    void filtersByToOnlyInPostgres() throws Exception {
        seed(
                event(14227L, WINDOW_TO.minus(1, ChronoUnit.DAYS), WINDOW_FROM, "/before", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_TO, WINDOW_FROM, "/at-to", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_TO.plus(1, ChronoUnit.DAYS), WINDOW_FROM, "/after", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL).param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/before"));
    }

    @Test
    void fromBoundaryIsIncludedAndToBoundaryIsExcluded() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/at-from", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_TO, WINDOW_FROM, "/at-to", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL)
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/at-from"));
    }

    @Test
    void filtersByCategoryInPostgres() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/injection", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/xss", RuleCategory.XSS, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL).param("category", "XSS"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/xss"))
                .andExpect(jsonPath("$.events[0].rule.category").value("XSS"));
    }

    @Test
    void filtersByActionInPostgres() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/deny", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/alert", RuleCategory.INJECTION, Action.ALERT));

        mockMvc.perform(get(SAMPLES_URL).param("action", "ALERT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/alert"))
                .andExpect(jsonPath("$.events[0].action").value("ALERT"));
    }

    // testing the And operator
    @Test
    void combinationOfFiltersAppliedTogether() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/match", RuleCategory.BOT, Action.MONITOR),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/wrong-category", RuleCategory.INJECTION, Action.MONITOR),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/wrong-action", RuleCategory.BOT, Action.DENY),
                event(99999L, WINDOW_FROM, WINDOW_FROM, "/wrong-config", RuleCategory.BOT, Action.MONITOR));

        mockMvc.perform(get(SAMPLES_URL)
                        .param("configId", "14227")
                        .param("category", "BOT")
                        .param("action", "MONITOR")
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/match"));
    }

    // Samples API filter events by eventTimestamp (and not receivedAt)
    @Test
    void timestampFilteringIsIndependentOfReceivedAt() throws Exception {
        seed(
                // event timestamp inside the window, receivedAt far outside it: must still be included
                event(14227L, WINDOW_FROM, Instant.parse("2020-01-01T00:00:00Z"), "/included", RuleCategory.INJECTION, Action.DENY),
                // event timestamp outside the window, receivedAt inside it: must be excluded
                event(14227L, WINDOW_FROM.minus(1, ChronoUnit.DAYS), WINDOW_FROM, "/excluded", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL)
                        .param("from", WINDOW_FROM.toString())
                        .param("to", WINDOW_TO.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(1))
                .andExpect(jsonPath("$.events[0].path").value("/included"));
    }

    // correct totalCount and total count
    @Test
    void paginationAndTotalCountAreCorrect() throws Exception {
        List<SecurityEventEntity> events = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            events.add(event(14227L, WINDOW_FROM.plus(i, ChronoUnit.MINUTES), WINDOW_FROM,
                    "/p" + i, RuleCategory.INJECTION, Action.DENY));
        }
        seed(events.toArray(new SecurityEventEntity[0]));

        mockMvc.perform(get(SAMPLES_URL).param("limit", "10").param("offset", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(25))
                .andExpect(jsonPath("$.limit").value(10))
                .andExpect(jsonPath("$.offset").value(0))
                .andExpect(jsonPath("$.events.length()").value(10));

        mockMvc.perform(get(SAMPLES_URL).param("limit", "10").param("offset", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(25))
                .andExpect(jsonPath("$.events.length()").value(5));
    }

    @Test
    void resultsAreSortedByEventTimestampDescending() throws Exception {
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/oldest", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM.plus(1, ChronoUnit.HOURS), WINDOW_FROM, "/middle", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM.plus(2, ChronoUnit.HOURS), WINDOW_FROM, "/newest", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events[0].path").value("/newest"))
                .andExpect(jsonPath("$.events[1].path").value("/middle"))
                .andExpect(jsonPath("$.events[2].path").value("/oldest"));
    }

    @Test
    void tiesOnEqualTimestampAreBrokenByIdDescending() throws Exception {
        // Same event_timestamp for all three; IDENTITY generation assigns ids in insertion
        // order, so id DESC means most-recently-inserted first.
        seed(
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/first-inserted", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/second-inserted", RuleCategory.INJECTION, Action.DENY),
                event(14227L, WINDOW_FROM, WINDOW_FROM, "/third-inserted", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events[0].path").value("/third-inserted"))
                .andExpect(jsonPath("$.events[1].path").value("/second-inserted"))
                .andExpect(jsonPath("$.events[2].path").value("/first-inserted"));
    }

    // testing offset and limit
    @Test
    void arbitraryOffsetNotAlignedToLimitReturnsCorrectSlice() throws Exception {
        List<SecurityEventEntity> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(event(14227L, WINDOW_FROM.plus(i, ChronoUnit.MINUTES), WINDOW_FROM,
                    "/p" + i, RuleCategory.INJECTION, Action.DENY));
        }
        seed(events.toArray(new SecurityEventEntity[0]));

        // Descending order is p9, p8, ..., p0. limit=3, offset=2 must return p7, p6, p5 -
        // not what PageRequest.of(offset / limit, limit) (i.e. page 0) would incorrectly return.
        mockMvc.perform(get(SAMPLES_URL).param("limit", "3").param("offset", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(10))
                .andExpect(jsonPath("$.events.length()").value(3))
                .andExpect(jsonPath("$.events[0].path").value("/p7"))
                .andExpect(jsonPath("$.events[1].path").value("/p6"))
                .andExpect(jsonPath("$.events[2].path").value("/p5"));
    }

    @Test
    void noMatchingRecordsReturnsEmptyResult() throws Exception {
        seed(event(14227L, WINDOW_FROM, WINDOW_FROM, "/p1", RuleCategory.INJECTION, Action.DENY));

        mockMvc.perform(get(SAMPLES_URL).param("configId", "99999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCount").value(0))
                .andExpect(jsonPath("$.events").isEmpty());
    }
}
