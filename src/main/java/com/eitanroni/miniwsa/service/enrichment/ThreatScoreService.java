package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.Severity;
import org.springframework.stereotype.Component;

/**
 * Pure, deterministic threat-score calculation. Never touches persistence.
 * With the current rule set the maximum achievable score is 90
 * (CRITICAL 40 + DENY 20 + sensitive-path 15 + repeat-offender 15); the 0-100
 * cap is still enforced in case the rules change in the future.
 */
@Component
public class ThreatScoreService {

    static final int SEVERITY_CRITICAL_POINTS = 40;
    static final int SEVERITY_HIGH_POINTS = 30;
    static final int SEVERITY_MEDIUM_POINTS = 20;
    static final int SEVERITY_LOW_POINTS = 10;

    static final int ACTION_DENY_POINTS = 20;
    static final int ACTION_ALERT_POINTS = 10;
    static final int ACTION_MONITOR_POINTS = 0;

    static final int SENSITIVE_PATH_BONUS = 15;
    static final int REPEAT_OFFENDER_BONUS = 15;

    static final int MIN_SCORE = 0;
    static final int MAX_SCORE = 100;

    private static final String SENSITIVE_PATH_ADMIN = "/admin";
    private static final String SENSITIVE_PATH_LOGIN = "/login";

    public int calculate(Severity severity, Action action, String path, boolean repeatOffender) {
        int score = severityPoints(severity) + actionPoints(action);

        if (containsSensitivePath(path)) {
            score += SENSITIVE_PATH_BONUS;
        }

        if (repeatOffender) {
            score += REPEAT_OFFENDER_BONUS;
        }

        return Math.max(MIN_SCORE, Math.min(score, MAX_SCORE));
    }

    private int severityPoints(Severity severity) {
        return switch (severity) {
            case CRITICAL -> SEVERITY_CRITICAL_POINTS;
            case HIGH -> SEVERITY_HIGH_POINTS;
            case MEDIUM -> SEVERITY_MEDIUM_POINTS;
            case LOW -> SEVERITY_LOW_POINTS;
        };
    }

    private int actionPoints(Action action) {
        return switch (action) {
            case DENY -> ACTION_DENY_POINTS;
            case ALERT -> ACTION_ALERT_POINTS;
            case MONITOR -> ACTION_MONITOR_POINTS;
        };
    }

    private boolean containsSensitivePath(String path) {
        return path != null && (path.contains(SENSITIVE_PATH_ADMIN) || path.contains(SENSITIVE_PATH_LOGIN));
    }
}
