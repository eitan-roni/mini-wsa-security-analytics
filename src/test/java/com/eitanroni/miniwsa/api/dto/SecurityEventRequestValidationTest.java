package com.eitanroni.miniwsa.api.dto;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityEventRequestValidationTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidatorFactory() {
        validatorFactory.close();
    }

    private RuleRequest validRule() {
        return new RuleRequest("950001", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, RuleCategory.INJECTION);
    }

    private GeoLocationRequest validGeoLocation(String city) {
        return new GeoLocationRequest("US", city);
    }

    private SecurityEventRequest validEvent() {
        return new SecurityEventRequest(
                "event-1",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                validRule(),
                Action.DENY,
                validGeoLocation("San Francisco"),
                512L,
                0L
        );
    }

    // happy test
    @Test
    void fullyValidEventHasNoViolations() {
        Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(validEvent());

        assertThat(violations).isEmpty();
    }

    // missing required param (eventId)
    @Test
    void missingRequiredTopLevelFieldCausesViolation() {
        SecurityEventRequest event = new SecurityEventRequest(
                "",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                validRule(),
                Action.DENY,
                validGeoLocation("San Francisco"),
                512L,
                0L
        );

        Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(event);

        assertThat(violations)
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("eventId"));
    }

    // invalid rule.category
    @Test
    void invalidNestedRuleCausesViolation() {
        RuleRequest invalidRule = new RuleRequest("", "SQL_INJECTION", "SQL Injection Attack Detected", Severity.CRITICAL, null);
        SecurityEventRequest event = new SecurityEventRequest(
                "event-1",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                invalidRule,
                Action.DENY,
                validGeoLocation("San Francisco"),
                512L,
                0L
        );

        Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(event);

        assertThat(violations)
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("rule.id"));
        assertThat(violations)
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("rule.category"));
    }

    // negative numeric param (requestSize)
    @Test
    void negativeRequestSizeCausesViolation() {
        SecurityEventRequest event = new SecurityEventRequest(
                "event-1",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                "Mozilla/5.0",
                validRule(),
                Action.DENY,
                validGeoLocation("San Francisco"),
                -1L,
                0L
        );

        Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(event);

        assertThat(violations)
                .anyMatch(violation -> violation.getPropertyPath().toString().equals("requestSize"));
    }

    // missing optional params (userAgent , city)
    @Test
    void optionalCityAndUserAgentMayBeNull() {
        SecurityEventRequest event = new SecurityEventRequest(
                "event-1",
                Instant.parse("2026-07-11T10:15:30Z"),
                14227L,
                "policy-1",
                "203.0.113.10",
                "example.com",
                "/login",
                "POST",
                403,
                null,
                validRule(),
                Action.DENY,
                validGeoLocation(null),
                512L,
                0L
        );

        Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(event);

        assertThat(violations).isEmpty();
    }
}