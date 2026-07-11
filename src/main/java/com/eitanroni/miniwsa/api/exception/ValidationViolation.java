package com.eitanroni.miniwsa.api.exception;

public record ValidationViolation(
        String field,
        String message
) {
}
