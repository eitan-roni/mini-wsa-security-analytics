package com.eitanroni.miniwsa.persistence.repository.projection;

import com.eitanroni.miniwsa.domain.Action;

public interface ActionStatsProjection {

    Action getAction();

    long getCount();
}
