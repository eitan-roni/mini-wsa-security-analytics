package com.eitanroni.miniwsa.api.exception;

import java.util.List;

public record ApiError(
        int status,
        String error,
        String path,
        List<ValidationViolation> violations
) {
}
