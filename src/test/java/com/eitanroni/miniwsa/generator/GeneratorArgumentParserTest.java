package com.eitanroni.miniwsa.generator;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeneratorArgumentParserTest {

    @Test
    void defaultsAreUsedWhenNoArgsGiven() {
        GeneratorConfig config = GeneratorArgumentParser.parse(new String[0]);

        assertThat(config.count()).isEqualTo(GeneratorConfig.DEFAULT_COUNT);
        assertThat(config.output()).isEqualTo(GeneratorConfig.DEFAULT_OUTPUT);
        assertThat(config.wavePercentage()).isEqualTo(GeneratorConfig.DEFAULT_WAVE_PERCENTAGE);
        assertThat(config.waveSize()).isEqualTo(GeneratorConfig.DEFAULT_WAVE_SIZE);
        assertThat(config.batchSize()).isEqualTo(GeneratorConfig.DEFAULT_BATCH_SIZE);
        assertThat(config.apiUrl()).isNull();
        assertThat(config.hasApiUrl()).isFalse();
        assertThat(config.idPrefix()).isEqualTo("gen-" + config.seed());
    }

    @Test
    void everyOptionIsParsedWhenProvided() {
        String[] args = {
                "--count", "10000",
                "--output", "out.json",
                "--seed", "42",
                "--wave-percentage", "50",
                "--wave-size", "8",
                "--api-url", "http://localhost:8080/v1/events/ingest",
                "--batch-size", "100",
                "--id-prefix", "run-abc"
        };

        GeneratorConfig config = GeneratorArgumentParser.parse(args);

        assertThat(config.count()).isEqualTo(10000);
        assertThat(config.output()).isEqualTo("out.json");
        assertThat(config.seed()).isEqualTo(42L);
        assertThat(config.wavePercentage()).isEqualTo(50);
        assertThat(config.waveSize()).isEqualTo(8);
        assertThat(config.apiUrl()).isEqualTo("http://localhost:8080/v1/events/ingest");
        assertThat(config.hasApiUrl()).isTrue();
        assertThat(config.batchSize()).isEqualTo(100);
        assertThat(config.idPrefix()).isEqualTo("run-abc");
    }

    @Test
    void zeroCountIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--count", "0"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--count");
    }

    @Test
    void negativeCountIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--count", "-5"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--count");
    }

    @Test
    void negativeWavePercentageIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--wave-percentage", "-1"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--wave-percentage");
    }

    @Test
    void wavePercentageAboveOneHundredIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--wave-percentage", "101"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--wave-percentage");
    }

    @Test
    void waveSizeBelowSixIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--wave-size", "5"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--wave-size");
    }

    @Test
    void zeroBatchSizeIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--batch-size", "0"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--batch-size");
    }

    @Test
    void negativeBatchSizeIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--batch-size", "-10"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--batch-size");
    }

    @Test
    void unknownOptionIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--not-a-real-option", "value"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("Unknown option");
    }

    @Test
    void missingOptionValueIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--count"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("Missing value");
    }

    @Test
    void nonNumericCountIsRejected() {
        assertThatThrownBy(() -> GeneratorArgumentParser.parse(new String[]{"--count", "not-a-number"}))
                .isInstanceOf(GeneratorArgumentException.class)
                .hasMessageContaining("--count");
    }

    @Test
    void isHelpRequestedDetectsHelpFlagAnywhereInArgs() {
        assertThat(GeneratorArgumentParser.isHelpRequested(new String[]{"--help"})).isTrue();
        assertThat(GeneratorArgumentParser.isHelpRequested(new String[]{"--count", "10", "--help"})).isTrue();
        assertThat(GeneratorArgumentParser.isHelpRequested(new String[]{"--count", "10"})).isFalse();
        assertThat(GeneratorArgumentParser.isHelpRequested(new String[0])).isFalse();
    }
}
