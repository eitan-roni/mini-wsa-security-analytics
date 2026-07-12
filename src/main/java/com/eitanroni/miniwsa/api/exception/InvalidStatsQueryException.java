package com.eitanroni.miniwsa.api.exception;

import java.util.List;

public class InvalidStatsQueryException extends RuntimeException {

    private final List<ValidationViolation> violations;

    public InvalidStatsQueryException(List<ValidationViolation> violations) {
        super("Invalid stats query parameters");
        this.violations = violations;
    }

    public List<ValidationViolation> violations() {
        return violations;
    }
}
