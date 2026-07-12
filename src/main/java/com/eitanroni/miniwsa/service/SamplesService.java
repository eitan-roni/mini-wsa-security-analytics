package com.eitanroni.miniwsa.service;

import com.eitanroni.miniwsa.api.dto.SampleSearchResponse;

public interface SamplesService {

    SampleSearchResponse search(SampleSearchCriteria criteria);
}
