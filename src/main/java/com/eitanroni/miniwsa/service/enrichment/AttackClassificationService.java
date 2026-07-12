package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.domain.RuleCategory;
import org.springframework.stereotype.Component;

@Component
public class AttackClassificationService {

    public String classify(RuleCategory category) {
        return switch (category) {
            case INJECTION -> "SQL/Command Injection";
            case XSS -> "Cross-Site Scripting";
            case PROTOCOL_VIOLATION -> "Protocol Anomaly";
            case DATA_LEAKAGE -> "Data Exfiltration";
            case BOT -> "Bot Activity";
            case DOS -> "Denial of Service";
            case RATE_LIMIT -> "Rate Limiting";
        };
    }
}
