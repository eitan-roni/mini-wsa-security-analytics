package com.eitanroni.miniwsa.generator;

import com.eitanroni.miniwsa.api.dto.SecurityEventRequest;
import com.eitanroni.miniwsa.domain.Action;
import com.eitanroni.miniwsa.domain.RuleCategory;
import com.eitanroni.miniwsa.domain.Severity;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityEventGeneratorTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-07-12T12:00:00Z"), ZoneOffset.UTC);
    private static final String FIXED_ID_PREFIX = "test-fixed";

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidatorFactory() {
        validatorFactory.close();
    }

    private GeneratorConfig config(int count, long seed, int wavePercentage, int waveSize) {
        return new GeneratorConfig(count, "unused.json", seed, wavePercentage, waveSize, null,
                GeneratorConfig.DEFAULT_BATCH_SIZE, FIXED_ID_PREFIX);
    }

    // happy test (correct events, no duplicated eventId, correct wave percent)
    @Test
    void tenThousandEventsAreGeneratedExactlyWithUniqueIdsAndWaves() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);

        GeneratedDataset dataset = generator.generate(config(10_000, 1L, 30, 10));

        assertThat(dataset.events()).hasSize(10_000);

        Set<String> ids = dataset.events().stream().map(SecurityEventRequest::eventId).collect(Collectors.toSet());
        assertThat(ids).hasSize(10_000);

        assertThat(dataset.waveEventCount()).isEqualTo(3000);
    }

    // testing Jakarta Validations
    @Test
    void everyGeneratedEventPassesBeanValidation() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(500, 7L, 30, 10));

        for (SecurityEventRequest event : dataset.events()) {
            Set<ConstraintViolation<SecurityEventRequest>> violations = validator.validate(event);
            assertThat(violations).as("violations for %s", event.eventId()).isEmpty();
        }
    }

    @Test
    void largeDeterministicDatasetCoversAllCategoriesActionsAndSeverities() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(2000, 99L, 30, 10));

        Set<RuleCategory> categories = dataset.events().stream()
                .map(event -> event.rule().category())
                .collect(Collectors.toSet());
        Set<Action> actions = dataset.events().stream()
                .map(SecurityEventRequest::action)
                .collect(Collectors.toSet());
        Set<Severity> severities = dataset.events().stream()
                .map(event -> event.rule().severity())
                .collect(Collectors.toSet());

        assertThat(categories).containsExactlyInAnyOrder(RuleCategory.values());
        assertThat(actions).containsExactlyInAnyOrder(Action.values());
        assertThat(severities).containsExactlyInAnyOrder(Severity.values());
    }

    // two equals data sets (the same seed and time)
    @Test
    void sameSeedAndClockProduceIdenticalDataset() {
        GeneratedDataset datasetA = new SecurityEventGenerator(FIXED_CLOCK).generate(config(300, 55L, 30, 10));
        GeneratedDataset datasetB = new SecurityEventGenerator(FIXED_CLOCK).generate(config(300, 55L, 30, 10));

        assertThat(datasetA.events()).isEqualTo(datasetB.events());
    }

    @Test
    void differentSeedsProduceDifferentDatasets() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);

        GeneratedDataset datasetA = generator.generate(config(300, 1L, 30, 10));
        GeneratedDataset datasetB = generator.generate(config(300, 2L, 30, 10));

        assertThat(datasetA.events()).isNotEqualTo(datasetB.events());
    }

    // testing the repeat offender - at least 6 events with the same ip and path withing 10 minutes
    @Test
    void attackWaveSharesClientIpAndPathAndFitsWithinTenMinutes() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(100, 3L, 50, 10));

        Map<String, List<SecurityEventRequest>> groupedByIpAndPath = dataset.events().stream()
                .collect(Collectors.groupingBy(event -> event.clientIp() + "|" + event.path()));

        List<SecurityEventRequest> wave = groupedByIpAndPath.values().stream()
                .filter(group -> group.size() >= 6)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected at least one wave with >= 6 events"));

        Instant earliest = wave.stream().map(SecurityEventRequest::timestamp).min(Instant::compareTo).orElseThrow();
        Instant latest = wave.stream().map(SecurityEventRequest::timestamp).max(Instant::compareTo).orElseThrow();
        assertThat(Duration.between(earliest, latest)).isLessThan(Duration.ofMinutes(10));

        assertThat(wave.stream().map(SecurityEventRequest::clientIp).collect(Collectors.toSet())).hasSize(1);
        assertThat(wave.stream().map(SecurityEventRequest::path).collect(Collectors.toSet())).hasSize(1);
    }

    @Test
    void countSmallerThanWaveSizeStillGeneratesExactCountWithoutFailing() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(3, 4L, 100, 10));

        assertThat(dataset.events()).hasSize(3);
        assertThat(dataset.waveEventCount()).isZero();
    }

    // generator not loosing events when wave sizes not equal
    @Test
    void countNotDivisibleByWaveSizeStillGeneratesExactCount() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(25, 5L, 100, 10));

        assertThat(dataset.events()).hasSize(25);
        assertThat(dataset.waveEventCount()).isEqualTo(20);
    }

    @Test
    void zeroWavePercentageProducesNoWaveEvents() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(200, 6L, 0, 10));

        assertThat(dataset.events()).hasSize(200);
        assertThat(dataset.waveEventCount()).isZero();
    }

    @Test
    void hundredPercentWavePercentageMaximizesWaveEvents() {
        SecurityEventGenerator generator = new SecurityEventGenerator(FIXED_CLOCK);
        GeneratedDataset dataset = generator.generate(config(205, 8L, 100, 10));

        assertThat(dataset.events()).hasSize(205);
        assertThat(dataset.waveEventCount()).isEqualTo(200);
    }
}
