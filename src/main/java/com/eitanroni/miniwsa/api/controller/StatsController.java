package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.StatsSummaryResponse;
import com.eitanroni.miniwsa.api.exception.InvalidStatsQueryException;
import com.eitanroni.miniwsa.api.exception.ValidationViolation;
import com.eitanroni.miniwsa.service.StatsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

@RestController
@RequestMapping("/v1/stats")
public class StatsController {

    private final StatsService statsService;

    public StatsController(StatsService statsService) {
        this.statsService = statsService;
    }

    @GetMapping("/summary")
    public StatsSummaryResponse summary(
            @RequestParam(required = false) Long configId,
            @RequestParam String from,
            @RequestParam String to) {
        Instant fromInstant = parseInstant("from", from);
        Instant toInstant = parseInstant("to", to);

        if (!fromInstant.isBefore(toInstant)) {
            throw new InvalidStatsQueryException(
                    List.of(new ValidationViolation("to", "must be after 'from'")));
        }

        return statsService.getSummary(configId, fromInstant, toInstant);
    }

    private Instant parseInstant(String field, String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw new InvalidStatsQueryException(
                    List.of(new ValidationViolation(field, "must be a valid ISO-8601 timestamp")));
        }
    }
}
