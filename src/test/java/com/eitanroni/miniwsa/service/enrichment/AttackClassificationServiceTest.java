package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.domain.RuleCategory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class AttackClassificationServiceTest {

    private final AttackClassificationService service = new AttackClassificationService();

    // the test runs separately for each argument.
    // in each test tested the return category and expectedAttackType values
    @ParameterizedTest
    @CsvSource({
            "INJECTION, SQL/Command Injection",
            "XSS, Cross-Site Scripting",
            "PROTOCOL_VIOLATION, Protocol Anomaly",
            "DATA_LEAKAGE, Data Exfiltration",
            "BOT, Bot Activity",
            "DOS, Denial of Service",
            "RATE_LIMIT, Rate Limiting"
    })
    void classifiesEveryCategory(RuleCategory category, String expectedAttackType) {
        assertThat(service.classify(category)).isEqualTo(expectedAttackType);
    }

    // verify that RuleCategory values are not null
    @Test
    void everyRuleCategoryIsMapped() {
        for (RuleCategory category : RuleCategory.values()) {
            assertThat(service.classify(category)).isNotBlank();
        }
    }
}
