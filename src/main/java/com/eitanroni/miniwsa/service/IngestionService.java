package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.EventIngestionResponse;
import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;

import java.util.List;

public interface IngestionService {

    EventIngestionResponse ingest(List<SecurityEventRequest> events);
}
