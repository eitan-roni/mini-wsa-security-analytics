package com.eitanroni.miniwsa.api.exception;

import java.util.List;

public class InvalidQueryParameterException extends RuntimeException {

    private final List<ValidationViolation> violations;

    public InvalidQueryParameterException(List<ValidationViolation> violations) {
        super("Invalid query parameters");
        this.violations = violations;
    }

    public List<ValidationViolation> violations() {
        return violations;
    }
}
