package com.eitanroni.miniwsa.generator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.PrintStream;
import java.time.Clock;

/**
 * Standalone command-line entry point for the security-event generator.
 * Does not start the Spring Boot application context and does not require
 * PostgreSQL to generate a file - only {@code --api-url} submission talks to
 * a running server.
 */
public final class SecurityEventGeneratorMain {

    private SecurityEventGeneratorMain() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /**
     * Testable entry point: returns a process exit code instead of calling
     * {@link System#exit(int)} directly, so tests can assert on it.
     */
    static int run(String[] args, PrintStream out, PrintStream err) {
        if (GeneratorArgumentParser.isHelpRequested(args)) {
            out.print(GeneratorArgumentParser.USAGE);
            return 0;
        }

        GeneratorConfig config;
        try {
            config = GeneratorArgumentParser.parse(args);
        } catch (GeneratorArgumentException ex) {
            err.println("Error: " + ex.getMessage());
            err.print(GeneratorArgumentParser.USAGE);
            return 1;
        }

        SecurityEventGenerator generator = new SecurityEventGenerator(Clock.systemUTC());
        GeneratedDataset dataset = generator.generate(config);

        try {
            new EventJsonWriter().write(dataset.events(), config.output());
        } catch (IOException ex) {
            err.println("Error: failed to write output file '" + config.output() + "': " + ex.getMessage());
            return 1;
        }

        out.println("Generated " + dataset.events().size() + " events");
        out.println("Attack-wave events: " + dataset.waveEventCount());
        out.println("Output: " + config.output());
        out.println("Seed: " + config.seed());

        if (config.hasApiUrl()) {
            return submit(config, dataset, out, err);
        }

        return 0;
    }

    private static int submit(GeneratorConfig config, GeneratedDataset dataset, PrintStream out, PrintStream err) {
        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        IngestionApiClient client = new IngestionApiClient(objectMapper);

        SubmissionResult result = client.submit(dataset.events(), config.apiUrl(), config.batchSize(), out);

        if (!result.success()) {
            err.println("Error: batch " + result.failedBatchNumber() + "/" + result.totalBatches()
                    + " failed - " + result.failureMessage());
            out.println("Submitted " + result.submittedEvents() + "/" + dataset.events().size() + " events before failure");
            return 1;
        }

        out.println("Submitted " + result.submittedEvents() + " events successfully");
        return 0;
    }
}
