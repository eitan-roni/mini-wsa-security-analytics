package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.persistence.repository.SecurityEventRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Determines whether an event qualifies for the repeat-offender threat-score
 * bonus, based on provisional assumptions pending interviewer clarification
 * (see README "Provisional repeat-offender assumptions").
 *
 * <p>The window is {@code [event.timestamp - 10 minutes, event.timestamp]}
 * (inclusive), keyed on {@code event.timestamp} (not {@code receivedAt}), and
 * the current event counts toward its own total. A client IP is a repeat
 * offender once the total count of matching events - previously persisted
 * rows plus earlier events in the same batch plus the event itself - exceeds
 * five.
 *
 * <p>Batch events are evaluated in event-timestamp ascending order, with
 * original request order as a tie-breaker for equal timestamps, so that
 * "earlier" always means earlier in that deterministic evaluation order, not
 * the order events appeared in the request.
 *
 * <p>Performance note: this issues one {@code COUNT} query per event against
 * {@code (client_ip, event_timestamp)} (an existing indexed column pair).
 * That is acceptable for this assignment's scale but does not scale to high
 * ingestion throughput; see the README for production-scale alternatives
 * (keyed streaming state, Redis, etc).
 */
@Component
public class RepeatOffenderService {

    static final Duration REPEAT_OFFENDER_WINDOW = Duration.ofMinutes(10);
    static final int REPEAT_OFFENDER_EVENT_COUNT_THRESHOLD = 5;

    private final SecurityEventRepository repository;

    public RepeatOffenderService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    /**
     * Evaluates every event in the batch and returns repeat-offender flags
     * aligned to the original (input) order of {@code events}.
     */
    public List<Boolean> evaluateBatch(List<SecurityEventRequest> events) {
        int size = events.size();
        Boolean[] resultsByOriginalIndex = new Boolean[size];

        // sorted events indices by timestamp
        List<Integer> evaluationOrder = IntStream.range(0, size)
                .boxed()
                .sorted(Comparator.<Integer, Instant>comparing(i -> events.get(i).timestamp())
                        .thenComparing(i -> i))
                .toList();

        // map Ip to list of timestamp
        Map<String, List<Instant>> evaluatedBatchTimestampsByIp = new HashMap<>();

        for (int index : evaluationOrder) {
            SecurityEventRequest event = events.get(index);
            String clientIp = event.clientIp();
            Instant eventTimestamp = event.timestamp();
            Instant windowStart = eventTimestamp.minus(REPEAT_OFFENDER_WINDOW);

            long persistedCount = repository.countByClientIpAndEventTimestampBetween(
                    clientIp, windowStart, eventTimestamp);

            // the entire Instants of current IP of current batch
            List<Instant> evaluatedTimestamps =
                    evaluatedBatchTimestampsByIp.computeIfAbsent(clientIp, ip -> new ArrayList<>());

             // only events counting from the calculated window
            long earlierBatchCount = evaluatedTimestamps.stream()
                    .filter(timestamp -> !timestamp.isBefore(windowStart))
                    .count();

            long totalCount = persistedCount + earlierBatchCount + 1;
            resultsByOriginalIndex[index] = totalCount > REPEAT_OFFENDER_EVENT_COUNT_THRESHOLD;

            evaluatedTimestamps.add(eventTimestamp);
        }

        return List.of(resultsByOriginalIndex);
    }
}
