package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.SampleSearchResponse;
import com.eitanroni.miniwsa.api.exception.InvalidQueryParameterException;
import com.eitanroni.miniwsa.api.exception.ValidationViolation;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.service.SampleSearchCriteria;
import com.eitanroni.miniwsa.service.SamplesService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/v1/events")
public class SamplesController {

    private static final int MIN_LIMIT = 1;
    private static final int MAX_LIMIT = 100;

    private final SamplesService samplesService;

    public SamplesController(SamplesService samplesService) {
        this.samplesService = samplesService;
    }

    @GetMapping("/samples")
    public SampleSearchResponse samples(
            @RequestParam(required = false) Long configId,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String action,
            @RequestParam(defaultValue = "20") int limit,
            @RequestParam(defaultValue = "0") int offset) {

        Instant fromInstant = from == null ? null : parseInstant("from", from);
        Instant toInstant = to == null ? null : parseInstant("to", to);

        if (fromInstant != null && toInstant != null && !fromInstant.isBefore(toInstant)) {
            throw new InvalidQueryParameterException(
                    List.of(new ValidationViolation("to", "must be after 'from'")));
        }

        RuleCategory categoryFilter = category == null ? null : parseEnum("category", category, RuleCategory.class);
        Action actionFilter = action == null ? null : parseEnum("action", action, Action.class);

        if (limit < MIN_LIMIT || limit > MAX_LIMIT) {
            throw new InvalidQueryParameterException(
                    List.of(new ValidationViolation("limit", "must be between 1 and 100")));
        }

        if (offset < 0) {
            throw new InvalidQueryParameterException(
                    List.of(new ValidationViolation("offset", "must not be negative")));
        }

        SampleSearchCriteria criteria = new SampleSearchCriteria(
                configId, fromInstant, toInstant, categoryFilter, actionFilter, limit, offset);

        return samplesService.search(criteria);
    }

    private Instant parseInstant(String field, String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            throw new InvalidQueryParameterException(
                    List.of(new ValidationViolation(field, "must be a valid ISO-8601 timestamp")));
        }
    }

    private <E extends Enum<E>> E parseEnum(String field, String value, Class<E> enumType) {
        try {
            return Enum.valueOf(enumType, value);
        } catch (IllegalArgumentException ex) {
            throw new InvalidQueryParameterException(
                    List.of(new ValidationViolation(field, "must be one of " + enumConstants(enumType))));
        }
    }

    private <E extends Enum<E>> List<String> enumConstants(Class<E> enumType) {
        return Arrays.stream(enumType.getEnumConstants()).map(Enum::name).toList();
    }
}
