package com.paloaltonetworks.prismaairs;

import software.amazon.awssdk.core.exception.SdkClientException;

/**
 * Thrown to the caller when a Prisma AIRS scan verdict blocks a Bedrock model call.
 *
 * <p>Unchecked on purpose: the AWS SDK for Java v2 rethrows {@code RuntimeException}s from
 * interceptor hooks unchanged (see {@code seam-notes.md}, section (b)), so this exact type reaches
 * the application on both scan legs:
 *
 * <ul>
 *   <li><b>prompt leg</b> — thrown from {@code beforeExecution}, before the request is marshalled,
 *       signed, or sent; nothing reached AWS and nothing was billed.</li>
 *   <li><b>response leg</b> — thrown from {@code afterExecution} (outside the SDK's retry loop, so
 *       it arrives unwrapped and is never retried); the model's response was received but is
 *       withheld from the application.</li>
 * </ul>
 *
 * <p>It extends {@link SdkClientException} so that the <em>async</em> client delivers the same type:
 * the async pipeline routes every failure through {@code ThrowableUtils.asSdkException}, which
 * returns an {@code SdkException} unchanged but wraps anything else in a bare
 * {@code SdkClientException}. A plain {@code RuntimeException} would therefore have reached the
 * caller as {@code CompletionException -> SdkClientException -> PrismaAirsBlockedException}, so a
 * typed {@code catch} (and the leg/category/scan id it carries) would have been missed. As an
 * {@code SdkClientException} it survives that hop, and the returned {@code CompletableFuture}
 * completes exceptionally with a {@code CompletionException} wrapping this type directly.
 *
 * <p>{@code retryable()} is {@code false} (inherited): a policy block is a decision, not a transport
 * fault, and re-issuing the call would only spend another scan on the same content.
 */
public final class PrismaAirsBlockedException extends SdkClientException {

    private static final long serialVersionUID = 1L;

    private final String leg;
    private final String category;
    private final String scanId;
    private final String reportId;
    private final String transactionId;
    private final String operation;
    private final String verdictJson;

    public PrismaAirsBlockedException(String leg, String category, String scanId, String reportId,
                                      String transactionId, String operation, String verdictJson) {
        super(SdkClientException.builder().message(String.format(
            "blocked by Prisma AIRS on the %s leg of %s (category=%s scan_id=%s transaction_id=%s)",
            leg, operation == null ? "a Bedrock call" : operation, category, scanId, transactionId)));
        this.leg = leg;
        this.category = category;
        this.scanId = scanId;
        this.reportId = reportId;
        this.transactionId = transactionId;
        this.operation = operation;
        this.verdictJson = verdictJson;
    }

    /** {@code "prompt"} or {@code "response"} — the scan leg that blocked. */
    public String leg() {
        return leg;
    }

    /** The verdict category (e.g. {@code "malicious"}), or {@code "airs_error"} for fail-closed blocks. */
    public String category() {
        return category;
    }

    /** The AIRS scan id, when the verdict carried one ({@code null} for fail-closed blocks). */
    public String scanId() {
        return scanId;
    }

    /** The AIRS report id, when the verdict carried one. */
    public String reportId() {
        return reportId;
    }

    /** The client-generated transaction id sent with (and echoed by) the scan. */
    public String transactionId() {
        return transactionId;
    }

    /** The Bedrock operation ({@code Converse}, {@code InvokeModel}, ...), when known. */
    public String operation() {
        return operation;
    }

    /** The raw verdict JSON as returned by the AIRS API, or {@code null} for fail-closed blocks. */
    public String verdictJson() {
        return verdictJson;
    }
}
