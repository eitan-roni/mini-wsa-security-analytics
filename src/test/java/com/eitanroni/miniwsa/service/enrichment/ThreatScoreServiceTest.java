package com.eitanroni.miniwsa.service.enrichment;

import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.Severity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ThreatScoreServiceTest {

    private final ThreatScoreService service = new ThreatScoreService();

    //Verifies that all threat-score components are combined correctly for a high-risk event
    @Test
    void criticalDenyLoginRepeatOffenderScores90() {
        int score = service.calculate(Severity.CRITICAL, Action.DENY, "/login", true);

        assertThat(score).isEqualTo(90);
    }

    @Test
    void highAlertAdminScores55() {
        int score = service.calculate(Severity.HIGH, Action.ALERT, "/admin", false);

        assertThat(score).isEqualTo(55);
    }

    @Test
    void mediumMonitorScores20() {
        int score = service.calculate(Severity.MEDIUM, Action.MONITOR, "/checkout", false);

        assertThat(score).isEqualTo(20);
    }

    @Test
    void lowMonitorScores10() {
        int score = service.calculate(Severity.LOW, Action.MONITOR, "/checkout", false);

        assertThat(score).isEqualTo(10);
    }

    // path contains both : /admin/login - only one bonus is added
    @Test
    void pathContainingBothAdminAndLoginReceivesOnlyOnePathBonus() {
        int withBoth = service.calculate(Severity.LOW, Action.MONITOR, "/admin/login", false);
        int withOne = service.calculate(Severity.LOW, Action.MONITOR, "/login", false);

        assertThat(withBoth).isEqualTo(withOne);
    }

    // two calculations : with and without repeat
    @Test
    void repeatOffenderAddsExactlyFifteen() {
        int withoutBonus = service.calculate(Severity.MEDIUM, Action.MONITOR, "/checkout", false);
        int withBonus = service.calculate(Severity.MEDIUM, Action.MONITOR, "/checkout", true);

        assertThat(withBonus - withoutBonus).isEqualTo(15);
    }

    @Test
    void nonRepeatOffenderAddsZero() {
        int score = service.calculate(Severity.MEDIUM, Action.MONITOR, "/checkout", false);

        assertThat(score).isEqualTo(20);
    }

    @Test
    void scoreIsCappedAtOneHundredEvenThoughCurrentRulesMaxOutAtNinety() {
        int score = service.calculate(Severity.CRITICAL, Action.DENY, "/admin/login", true);

        assertThat(score).isEqualTo(90);
        assertThat(score).isLessThanOrEqualTo(ThreatScoreService.MAX_SCORE);
    }
}
