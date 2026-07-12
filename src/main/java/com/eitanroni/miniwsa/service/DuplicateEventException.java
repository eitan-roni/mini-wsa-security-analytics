package com.eitanroni.miniwsa.service;

public class DuplicateEventException extends RuntimeException {

    public DuplicateEventException(String message, Throwable cause) {
        super(message, cause);
    }
}
