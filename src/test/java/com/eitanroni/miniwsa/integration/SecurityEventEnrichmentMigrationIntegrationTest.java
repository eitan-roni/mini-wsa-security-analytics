package com.eitanroni.miniwsa.integration;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that the V2 migration upgrades a database left at V1 by an older
 * deployment: a pre-existing, valid V1 row (no {@code attack_type} or
 * {@code threat_score}) must be backfilled with the same values the
 * application would compute for an equivalent event today. Runs Flyway
 * directly against the container (no Spring context) so the migration can be
 * stopped at V1 before the row is inserted.
 */
@Testcontainers
class SecurityEventEnrichmentMigrationIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    // upgrading existing system (verify old data is updated with the new schema)
    @Test
    void v2MigrationBackfillsAttackTypeAndThreatScoreForExistingV1Row() throws Exception {
        migrateTo("1");

        try (Connection connection = connect()) {
            insertValidV1Row(connection);
        }

        migrateToLatest();

        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT attack_type, threat_score FROM security_events WHERE event_id = ?")) {
            statement.setString(1, "evt-v1-upgrade");

            try (ResultSet resultSet = statement.executeQuery()) {
                assertThat(resultSet.next()).isTrue();
                assertThat(resultSet.getString("attack_type")).isEqualTo("SQL/Command Injection");
                // CRITICAL(40) + DENY(20) + sensitive path "/login"(15); the only row for
                // its client_ip, so the repeat-offender window count is 1, not > 5
                assertThat(resultSet.getInt("threat_score")).isEqualTo(75);
                assertThat(resultSet.next()).isFalse();
            }
        }
    }

    private void migrateTo(String target) {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .target(target)
                .load()
                .migrate();
    }

    private void migrateToLatest() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    private Connection connect() throws Exception {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private void insertValidV1Row(Connection connection) throws Exception {
        String sql = """
                INSERT INTO security_events (
                    event_id, event_timestamp, received_at, config_id, policy_id,
                    client_ip, hostname, path, http_method, status_code, user_agent,
                    rule_id, rule_name, rule_message, severity, category, action,
                    country, city, request_size, response_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        OffsetDateTime timestamp = OffsetDateTime.ofInstant(Instant.parse("2026-07-11T10:15:30Z"), ZoneOffset.UTC);

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, "evt-v1-upgrade");
            statement.setObject(2, timestamp);
            statement.setObject(3, timestamp);
            statement.setLong(4, 14227L);
            statement.setString(5, "policy-1");
            statement.setString(6, "203.0.113.10");
            statement.setString(7, "example.com");
            statement.setString(8, "/login");
            statement.setString(9, "POST");
            statement.setInt(10, 403);
            statement.setString(11, "Mozilla/5.0");
            statement.setString(12, "950001");
            statement.setString(13, "SQL_INJECTION");
            statement.setString(14, "SQL Injection Attack Detected");
            statement.setString(15, "CRITICAL");
            statement.setString(16, "INJECTION");
            statement.setString(17, "DENY");
            statement.setString(18, "US");
            statement.setString(19, "San Francisco");
            statement.setLong(20, 512L);
            statement.setLong(21, 0L);
            statement.executeUpdate();
        }
    }
}