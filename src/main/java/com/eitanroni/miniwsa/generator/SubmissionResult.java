package com.eitanroni.miniwsa.generator;

public record SubmissionResult(
        boolean success,
        int totalBatches,
        int completedBatches,
        int submittedEvents,
        int failedBatchNumber,
        String failureMessage
) {

    public static SubmissionResult success(int totalBatches, int submittedEvents) {
        return new SubmissionResult(true, totalBatches, totalBatches, submittedEvents, -1, null);
    }

    public static SubmissionResult failure(int failedBatchNumber, int totalBatches, int submittedEvents, String failureMessage) {
        return new SubmissionResult(false, totalBatches, failedBatchNumber - 1, submittedEvents, failedBatchNumber, failureMessage);
    }
}
