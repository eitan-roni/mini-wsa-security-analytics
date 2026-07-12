package com.eitanroni.miniwsa.api.exception;

import com.eitanroni.miniwsa.service.DuplicateEventException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationFailure(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<ValidationViolation> violations = ex.getBindingResult().getFieldErrors().stream()
                .map(this::toViolation)
                .toList();

        return buildResponse(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", request, violations);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleMalformedRequestBody(HttpMessageNotReadableException ex, HttpServletRequest request) {
        ValidationViolation violation = new ValidationViolation("body", "Request body is malformed or contains an invalid value");

        return buildResponse(HttpStatus.BAD_REQUEST, "MALFORMED_REQUEST_BODY", request, List.of(violation));
    }

    @ExceptionHandler(DuplicateEventException.class)
    public ResponseEntity<ApiError> handleDuplicateEvent(DuplicateEventException ex, HttpServletRequest request) {
        ValidationViolation violation = new ValidationViolation("eventId", ex.getMessage());

        return buildResponse(HttpStatus.CONFLICT, "DUPLICATE_EVENT", request, List.of(violation));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpectedError(Exception ex, HttpServletRequest request) {
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", request, List.of());
    }

    private ValidationViolation toViolation(FieldError fieldError) {
        return new ValidationViolation(fieldError.getField(), fieldError.getDefaultMessage());
    }

    private ResponseEntity<ApiError> buildResponse(HttpStatus status, String error, HttpServletRequest request,
                                                     List<ValidationViolation> violations) {
        ApiError body = new ApiError(status.value(), error, request.getRequestURI(), violations);
        return ResponseEntity.status(status).body(body);
    }
}
