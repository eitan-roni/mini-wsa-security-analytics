package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.GeoLocationRequest;
import com.eitanroni.miniwsa.api.dto.RuleRequest;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Generates synthetic-but-realistic {@link SecurityEventRequest} datasets
 * for {@code POST /v1/events/ingest}. Deterministic for a given
 * {@link GeneratorConfig#seed()} and injected {@link Clock}: the same seed
 * and clock always produce the same logical dataset (field values), though
 * the default {@code idPrefix} is derived from the resolved seed rather than
 * wall-clock time specifically so that determinism holds for event IDs too.
 *
 * <p>The final event list is shuffled (with the same seeded {@link Random})
 * before being returned, since a real ingestion batch would not arrive in
 * strict timestamp order; callers relying on chronological order should sort
 * by {@code timestamp} themselves.
 */
public class SecurityEventGenerator {

    private static final Duration LOOKBACK_WINDOW = Duration.ofHours(24);
    private static final Duration WAVE_MAX_DURATION = Duration.ofMinutes(9).plusSeconds(30);
    private static final Duration WAVE_MIN_DURATION = Duration.ofSeconds(30);
    private static final int CLIENT_IP_POOL_SIZE = 60;

    private static final List<Long> CONFIG_IDS = List.of(14227L, 18823L, 20591L, 30442L, 40118L);

    private static final List<String> POLICY_IDS =
            List.of("policy-1", "policy-2", "policy-3", "policy-waf-default", "policy-api-strict");

    private static final List<String> HOSTNAMES =
            List.of("api.example.com", "www.example.com", "shop.example.com", "admin.example.com", "cdn.example.com");

    private static final List<String> HTTP_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH");

    private static final List<String> USER_AGENTS = List.of(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
            "curl/8.4.0",
            "python-requests/2.31.0",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; SemrushBot/7~bl)");

    private record GeoPoint(String country, String city) {
    }

    private static final List<GeoPoint> GEO_POINTS = List.of(
            new GeoPoint("US", "San Francisco"),
            new GeoPoint("US", "New York"),
            new GeoPoint("US", "Seattle"),
            new GeoPoint("GB", "London"),
            new GeoPoint("DE", "Berlin"),
            new GeoPoint("IN", "Mumbai"),
            new GeoPoint("BR", "Sao Paulo"),
            new GeoPoint("JP", "Tokyo"),
            new GeoPoint("AU", "Sydney"),
            new GeoPoint("FR", "Paris"));

    private record RuleTemplate(String id, String name, String message) {
    }

    private static final Map<RuleCategory, List<String>> PATHS_BY_CATEGORY = Map.of(
            RuleCategory.INJECTION, List.of("/api/v1/login", "/admin/users", "/api/v1/search", "/api/v1/orders"),
            RuleCategory.XSS, List.of("/comments", "/api/v1/profile", "/search", "/api/v1/feedback"),
            RuleCategory.PROTOCOL_VIOLATION, List.of("/api/v1/upload", "/api/v2/data", "/api/v1/webhook"),
            RuleCategory.DATA_LEAKAGE, List.of("/api/v1/export", "/api/v1/reports", "/admin/backup", "/api/v1/customers"),
            RuleCategory.BOT, List.of("/", "/robots.txt", "/api/v1/products", "/pricing"),
            RuleCategory.DOS, List.of("/api/v1/checkout", "/login", "/api/v1/search"),
            RuleCategory.RATE_LIMIT, List.of("/api/v1/search", "/api/v1/login", "/api/v1/orders"));

    private static final Map<RuleCategory, List<RuleTemplate>> RULES_BY_CATEGORY = Map.of(
            RuleCategory.INJECTION, List.of(
                    new RuleTemplate("950001", "SQL_INJECTION", "SQL Injection Attack Detected"),
                    new RuleTemplate("950002", "COMMAND_INJECTION", "OS Command Injection Detected")),
            RuleCategory.XSS, List.of(
                    new RuleTemplate("941001", "XSS_ATTACK", "Cross-Site Scripting Attack Detected"),
                    new RuleTemplate("941002", "XSS_REFLECTED", "Reflected Cross-Site Scripting Detected")),
            RuleCategory.PROTOCOL_VIOLATION, List.of(
                    new RuleTemplate("920001", "PROTOCOL_ANOMALY", "HTTP Protocol Violation Detected"),
                    new RuleTemplate("920002", "INVALID_HEADER", "Malformed Request Header Detected")),
            RuleCategory.DATA_LEAKAGE, List.of(
                    new RuleTemplate("930001", "DATA_LEAKAGE", "Sensitive Data Exposure Detected"),
                    new RuleTemplate("930002", "PII_EXFILTRATION", "Personally Identifiable Information Exfiltration Detected")),
            RuleCategory.BOT, List.of(
                    new RuleTemplate("912001", "BOT_DETECTED", "Automated Bot Traffic Detected"),
                    new RuleTemplate("912002", "SCRAPER_DETECTED", "Content Scraper Detected")),
            RuleCategory.DOS, List.of(
                    new RuleTemplate("913001", "DOS_ATTACK", "Denial of Service Pattern Detected"),
                    new RuleTemplate("913002", "FLOOD_DETECTED", "Request Flood Detected")),
            RuleCategory.RATE_LIMIT, List.of(
                    new RuleTemplate("914001", "RATE_LIMIT_EXCEEDED", "Rate Limit Exceeded"),
                    new RuleTemplate("914002", "THROTTLE_TRIGGERED", "Request Throttling Triggered")));

    private static final List<RuleCategory> ALL_CATEGORIES = List.of(RuleCategory.values());
    private static final List<Severity> ALL_SEVERITIES = List.of(Severity.values());

    private static final List<RuleCategory> WAVE_CATEGORIES =
            List.of(RuleCategory.DOS, RuleCategory.RATE_LIMIT, RuleCategory.BOT, RuleCategory.INJECTION);

    private static final List<Severity> WAVE_SEVERITIES = List.of(Severity.CRITICAL, Severity.HIGH);

    private final Clock clock;

    public SecurityEventGenerator(Clock clock) {
        this.clock = clock;
    }

    public GeneratedDataset generate(GeneratorConfig config) {
        Random random = new Random(config.seed());
        Instant windowEnd = clock.instant();
        Instant windowStart = windowEnd.minus(LOOKBACK_WINDOW);

        int targetWaveEvents = (int) ((long) config.count() * config.wavePercentage() / 100);
        int numWaves = targetWaveEvents / config.waveSize();
        int waveEventTotal = numWaves * config.waveSize();
        int backgroundEventTotal = config.count() - waveEventTotal;

        List<String> clientIpPool = buildClientIpPool(random, CLIENT_IP_POOL_SIZE);

        List<SecurityEventRequest> events = new ArrayList<>(config.count());
        int nextId = 0;

        for (int w = 0; w < numWaves; w++) {
            List<SecurityEventRequest> wave = generateWave(random, windowStart, windowEnd, clientIpPool, config, nextId);
            events.addAll(wave);
            nextId += wave.size();
        }

        for (int i = 0; i < backgroundEventTotal; i++) {
            events.add(generateBackgroundEvent(random, windowStart, windowEnd, clientIpPool, config, nextId));
            nextId++;
        }

        Collections.shuffle(events, random);

        return new GeneratedDataset(List.copyOf(events), waveEventTotal);
    }

    private List<SecurityEventRequest> generateWave(Random random, Instant windowStart, Instant windowEnd,
                                                      List<String> clientIpPool, GeneratorConfig config, int startId) {
        String clientIp = pickFrom(random, clientIpPool);
        RuleCategory category = pickFrom(random, WAVE_CATEGORIES);
        String path = pickFrom(random, PATHS_BY_CATEGORY.get(category));
        RuleTemplate rule = pickFrom(random, RULES_BY_CATEGORY.get(category));
        Severity severity = pickFrom(random, WAVE_SEVERITIES);
        Action action = pickAction(random, severity);

        Instant latestWaveStart = windowEnd.minus(Duration.ofMinutes(10));
        Instant waveStart = randomInstantBetween(random, windowStart, latestWaveStart);
        long minSeconds = WAVE_MIN_DURATION.toSeconds();
        long maxSeconds = WAVE_MAX_DURATION.toSeconds();
        long waveDurationSeconds = minSeconds + random.nextInt((int) (maxSeconds - minSeconds));

        int waveSize = config.waveSize();
        List<SecurityEventRequest> wave = new ArrayList<>(waveSize);
        for (int i = 0; i < waveSize; i++) {
            long offsetSeconds = waveSize == 1 ? 0 : (waveDurationSeconds * i) / (waveSize - 1);
            Instant timestamp = waveStart.plusSeconds(offsetSeconds);
            String eventId = config.idPrefix() + "-" + (startId + i);
            wave.add(buildEvent(random, eventId, timestamp, clientIp, path, category, rule, severity, action));
        }
        return wave;
    }

    private SecurityEventRequest generateBackgroundEvent(Random random, Instant windowStart, Instant windowEnd,
                                                           List<String> clientIpPool, GeneratorConfig config, int id) {
        RuleCategory category = pickFrom(random, ALL_CATEGORIES);
        String path = pickFrom(random, PATHS_BY_CATEGORY.get(category));
        RuleTemplate rule = pickFrom(random, RULES_BY_CATEGORY.get(category));
        Severity severity = pickFrom(random, ALL_SEVERITIES);
        Action action = pickAction(random, severity);
        String clientIp = pickFrom(random, clientIpPool);
        Instant timestamp = randomInstantBetween(random, windowStart, windowEnd);
        String eventId = config.idPrefix() + "-" + id;

        return buildEvent(random, eventId, timestamp, clientIp, path, category, rule, severity, action);
    }

    private SecurityEventRequest buildEvent(Random random, String eventId, Instant timestamp, String clientIp,
                                             String path, RuleCategory category, RuleTemplate rule,
                                             Severity severity, Action action) {
        Long configId = pickFrom(random, CONFIG_IDS);
        String policyId = pickFrom(random, POLICY_IDS);
        String hostname = pickFrom(random, HOSTNAMES);
        String method = pickFrom(random, HTTP_METHODS);
        String userAgent = pickFrom(random, USER_AGENTS);
        int statusCode = pickStatusCode(random, category, action);
        GeoPoint geoPoint = pickFrom(random, GEO_POINTS);

        RuleRequest ruleRequest = new RuleRequest(rule.id(), rule.name(), rule.message(), severity, category);
        GeoLocationRequest geoLocationRequest = new GeoLocationRequest(geoPoint.country(), geoPoint.city());

        return new SecurityEventRequest(
                eventId,
                timestamp,
                configId,
                policyId,
                clientIp,
                hostname,
                path,
                method,
                statusCode,
                userAgent,
                ruleRequest,
                action,
                geoLocationRequest,
                requestSize(random),
                responseSize(random, category, action));
    }

    private Action pickAction(Random random, Severity severity) {
        return switch (severity) {
            case CRITICAL -> pickFrom(random, List.of(Action.DENY, Action.DENY, Action.ALERT));
            case HIGH -> pickFrom(random, List.of(Action.DENY, Action.ALERT, Action.ALERT));
            case MEDIUM -> pickFrom(random, List.of(Action.ALERT, Action.ALERT, Action.MONITOR));
            case LOW -> pickFrom(random, List.of(Action.MONITOR, Action.MONITOR, Action.ALERT));
        };
    }

    private int pickStatusCode(Random random, RuleCategory category, Action action) {
        if (category == RuleCategory.RATE_LIMIT) {
            return 429;
        }
        if (action == Action.DENY) {
            return random.nextBoolean() ? 403 : 401;
        }
        if (category == RuleCategory.BOT && action == Action.MONITOR) {
            return 200;
        }
        if (action == Action.MONITOR) {
            return pickFrom(random, List.of(200, 200, 301, 404));
        }
        return pickFrom(random, List.of(200, 403, 500));
    }

    private long requestSize(Random random) {
        return 200 + random.nextInt(4800);
    }

    private long responseSize(Random random, RuleCategory category, Action action) {
        if (category == RuleCategory.DATA_LEAKAGE) {
            return 50_000 + random.nextInt(450_000);
        }
        if (action == Action.DENY) {
            return random.nextInt(500);
        }
        return random.nextInt(20_000);
    }

    private List<String> buildClientIpPool(Random random, int size) {
        List<String> pool = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            pool.add(randomIp(random));
        }
        return pool;
    }

    private String randomIp(Random random) {
        return (random.nextInt(223) + 1) + "." + random.nextInt(256) + "." + random.nextInt(256) + "." + (random.nextInt(254) + 1);
    }

    private Instant randomInstantBetween(Random random, Instant start, Instant end) {
        long startMillis = start.toEpochMilli();
        long endMillis = end.toEpochMilli();
        long range = Math.max(1, endMillis - startMillis);
        long offset = (long) (random.nextDouble() * range);
        return Instant.ofEpochMilli(startMillis + offset);
    }

    private static <T> T pickFrom(Random random, List<T> options) {
        return options.get(random.nextInt(options.size()));
    }
}
