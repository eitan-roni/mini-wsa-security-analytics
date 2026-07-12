package com.eitanroni.miniwsa.generator;

public record GeneratorConfig(
        int count,
        String output,
        long seed,
        int wavePercentage,
        int waveSize,
        String apiUrl,
        int batchSize,
        String idPrefix
) {

    public static final int DEFAULT_COUNT = 1000;
    public static final String DEFAULT_OUTPUT = "generated-security-events.json";
    public static final int DEFAULT_WAVE_PERCENTAGE = 30;
    public static final int DEFAULT_WAVE_SIZE = 10;
    public static final int MIN_WAVE_SIZE = 6;
    public static final int DEFAULT_BATCH_SIZE = 250;

    public boolean hasApiUrl() {
        return apiUrl != null && !apiUrl.isBlank();
    }
}
