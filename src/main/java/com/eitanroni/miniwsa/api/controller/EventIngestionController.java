package com.eitanroni.miniwsa.api.controller;

import com.eitanroni.miniwsa.api.dto.EventIngestionRequest;
import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.service.IngestionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/v1/events")
public class EventIngestionController {

    private final IngestionService ingestionService;

    public EventIngestionController(IngestionService ingestionService) {
        this.ingestionService = ingestionService;
    }

    @PostMapping("/ingest")
    @ResponseStatus(HttpStatus.CREATED)
    public EventIngestionResponse ingest(@Valid @RequestBody EventIngestionRequest request) {
        return ingestionService.ingest(request.events());
    }
}
