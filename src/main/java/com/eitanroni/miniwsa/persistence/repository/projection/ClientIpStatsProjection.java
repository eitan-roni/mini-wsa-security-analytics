package com.eitanroni.miniwsa.persistence.repository.projection;

public interface ClientIpStatsProjection {

    String getClientIp();

    long getCount();

    Double getAvgThreatScore();
}
