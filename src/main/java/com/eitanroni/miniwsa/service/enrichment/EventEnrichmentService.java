package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates classification, threat scoring, and repeat-offender
 * evaluation for a batch of validated events. Returns enriched events in the
 * same order as the input list.
 */
@Component
public class EventEnrichmentService {

    private final AttackClassificationService classificationService;
    private final ThreatScoreService threatScoreService;
    private final RepeatOffenderService repeatOffenderService;

    public EventEnrichmentService(AttackClassificationService classificationService,
                                   ThreatScoreService threatScoreService,
                                   RepeatOffenderService repeatOffenderService) {
        this.classificationService = classificationService;
        this.threatScoreService = threatScoreService;
        this.repeatOffenderService = repeatOffenderService;
    }

    public List<EnrichedSecurityEvent> enrich(List<SecurityEventRequest> events, Instant receivedAt) {
        List<Boolean> repeatOffenderFlags = repeatOffenderService.evaluateBatch(events);

        List<EnrichedSecurityEvent> enrichedEvents = new ArrayList<>(events.size());
        for (int i = 0; i < events.size(); i++) {
            SecurityEventRequest event = events.get(i);
            String attackType = classificationService.classify(event.rule().category());
            int threatScore = threatScoreService.calculate(
                    event.rule().severity(),
                    event.action(),
                    event.path(),
                    repeatOffenderFlags.get(i));

            enrichedEvents.add(new EnrichedSecurityEvent(event, receivedAt, attackType, threatScore));
        }

        return enrichedEvents;
    }
}
