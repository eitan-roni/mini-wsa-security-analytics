package com.eitanroni.miniwsa.generator;

import java.util.Arrays;

/**
 * Hand-rolled {@code --option value} parser. A small, dependency-free parser
 * is preferred over a CLI framework for the handful of options this
 * generator supports.
 */
public final class GeneratorArgumentParser {

    public static final String USAGE = """
            Usage: SecurityEventGeneratorMain [OPTIONS]

            Generates synthetic security events for POST /v1/events/ingest.

            Options:
              --count <n>             Total number of events to generate (default: %d, must be > 0)
              --output <file>         Output JSON file path (default: %s)
              --seed <n>              Random seed for reproducible generation (default: derived from current time)
              --wave-percentage <n>   Approximate percentage of events belonging to attack waves, 0-100 (default: %d)
              --wave-size <n>         Number of events per attack wave, must be >= %d (default: %d)
              --api-url <url>         Ingestion endpoint to submit generated events to (default: none, file only)
              --batch-size <n>        Events per HTTP batch when --api-url is set, must be > 0 (default: %d)
              --id-prefix <prefix>    Prefix for generated event IDs (default: gen-<seed>)
              --help                  Show this help message
            """.formatted(
            GeneratorConfig.DEFAULT_COUNT,
            GeneratorConfig.DEFAULT_OUTPUT,
            GeneratorConfig.DEFAULT_WAVE_PERCENTAGE,
            GeneratorConfig.MIN_WAVE_SIZE,
            GeneratorConfig.DEFAULT_WAVE_SIZE,
            GeneratorConfig.DEFAULT_BATCH_SIZE);

    private GeneratorArgumentParser() {
    }

    public static boolean isHelpRequested(String[] args) {
        return Arrays.asList(args).contains("--help");
    }

    public static GeneratorConfig parse(String[] args) {
        int count = GeneratorConfig.DEFAULT_COUNT;
        String output = GeneratorConfig.DEFAULT_OUTPUT;
        Long seed = null;
        int wavePercentage = GeneratorConfig.DEFAULT_WAVE_PERCENTAGE;
        int waveSize = GeneratorConfig.DEFAULT_WAVE_SIZE;
        String apiUrl = null;
        int batchSize = GeneratorConfig.DEFAULT_BATCH_SIZE;
        String idPrefix = null;

        int i = 0;
        while (i < args.length) {
            String option = args[i];
            String value = nextValue(args, i, option);

            switch (option) {
                case "--count" -> count = parseInt(option, value);
                case "--output" -> output = value;
                case "--seed" -> seed = parseLong(option, value);
                case "--wave-percentage" -> wavePercentage = parseInt(option, value);
                case "--wave-size" -> waveSize = parseInt(option, value);
                case "--api-url" -> apiUrl = value;
                case "--batch-size" -> batchSize = parseInt(option, value);
                case "--id-prefix" -> idPrefix = value;
                default -> throw new GeneratorArgumentException("Unknown option: " + option);
            }
            i += 2;
        }

        if (count <= 0) {
            throw new GeneratorArgumentException("--count must be greater than zero, was: " + count);
        }
        if (wavePercentage < 0 || wavePercentage > 100) {
            throw new GeneratorArgumentException("--wave-percentage must be between 0 and 100, was: " + wavePercentage);
        }
        if (waveSize < GeneratorConfig.MIN_WAVE_SIZE) {
            throw new GeneratorArgumentException(
                    "--wave-size must be at least " + GeneratorConfig.MIN_WAVE_SIZE + ", was: " + waveSize);
        }
        if (batchSize <= 0) {
            throw new GeneratorArgumentException("--batch-size must be greater than zero, was: " + batchSize);
        }

        long resolvedSeed = seed != null ? seed : System.nanoTime();
        String resolvedIdPrefix = idPrefix != null ? idPrefix : "gen-" + resolvedSeed;

        return new GeneratorConfig(count, output, resolvedSeed, wavePercentage, waveSize, apiUrl, batchSize, resolvedIdPrefix);
    }

    private static String nextValue(String[] args, int index, String option) {
        if (index + 1 >= args.length) {
            throw new GeneratorArgumentException("Missing value for option: " + option);
        }
        return args[index + 1];
    }

    private static int parseInt(String option, String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            throw new GeneratorArgumentException("Invalid numeric value for " + option + ": " + value);
        }
    }

    private static long parseLong(String option, String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ex) {
            throw new GeneratorArgumentException("Invalid numeric value for " + option + ": " + value);
        }
    }
}
