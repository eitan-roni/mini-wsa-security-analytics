package com.eitanroni.miniwsa.persistence.repository.projection;

import com.eitanroni.miniwsa.domain.RuleCategory;

public interface CategoryStatsProjection {

    RuleCategory getCategory();

    long getCount();

    Double getAvgThreatScore();
}
