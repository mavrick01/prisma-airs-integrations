package com.paloaltonetworks.prismaairs;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.services.bedrockruntime.model.Citation;
import software.amazon.awssdk.services.bedrockruntime.model.CitationGeneratedContent;
import software.amazon.awssdk.services.bedrockruntime.model.CitationSourceContent;
import software.amazon.awssdk.services.bedrockruntime.model.CitationsContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.ContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.ConversationRole;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseOutput;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseRequest;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseResponse;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseStreamRequest;
import software.amazon.awssdk.services.bedrockruntime.model.GuardrailConverseContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelRequest;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelResponse;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelWithResponseStreamRequest;
import software.amazon.awssdk.services.bedrockruntime.model.Message;
import software.amazon.awssdk.services.bedrockruntime.model.SearchResultBlock;
import software.amazon.awssdk.services.bedrockruntime.model.SearchResultContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.StopReason;
import software.amazon.awssdk.services.bedrockruntime.model.SystemContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.ToolResultContentBlock;

/**
 * Prisma AIRS scan hook for AWS SDK for Java v2 Bedrock Runtime clients.
 *
 * <p>An {@link ExecutionInterceptor} that scans EVERY Bedrock model invocation made through a
 * client it is registered on — including calls a framework makes on the application's behalf:
 *
 * <ul>
 *   <li>{@code beforeExecution} — the outbound prompt is scanned; a blocked prompt never leaves
 *       the process (the request is not marshalled, not signed, not sent, and never billed — the
 *       hook runs before the SDK's request pipeline, and therefore before {@code SigningStage}).</li>
 *   <li>{@code modifyResponse} — the model's response is scanned before the application sees it;
 *       a blocked response is withheld (raised from {@code afterExecution}) or replaced with a
 *       well-formed {@code CONTENT_FILTERED} response.</li>
 * </ul>
 *
 * <p>A Bedrock guardrail is a request parameter: every call site must remember to pass it, and a
 * call without it is silently unguarded. An {@code ExecutionInterceptor} is registered on the
 * client — or, listed in the classpath resource file
 * {@code software/amazon/awssdk/global/handlers/execution.interceptors}, on <em>every AWS SDK
 * client in the JVM</em> — and applies to every call made through it.
 *
 * <p>Single class plus one exception type; depends only on {@code bedrockruntime} (whose transitive
 * core supplies the SDK's own JSON support, {@code software.amazon.awssdk.protocols.jsoncore}).
 * Covers {@code Converse}, {@code ConverseStream}, {@code InvokeModel}, and
 * {@code InvokeModelWithResponseStream}; all other operations and services pass through untouched.
 *
 * <p>Environment variables (standard Prisma AIRS names):
 *
 * <pre>
 *   PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
 *   PRISMA_AIRS_PROFILE_NAME   required   security profile name (or set profileName/profileId)
 *   PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region
 * </pre>
 *
 * <p>Usage:
 *
 * <pre>{@code
 * BedrockRuntimeClient bedrock = BedrockRuntimeClient.builder()
 *     .overrideConfiguration(o -> o.addExecutionInterceptor(
 *         PrismaAirsInterceptor.builder().appName("support-chat").build()))
 *     .build();
 *
 * bedrock.converse(...);   // scanned, both directions
 * }</pre>
 *
 * <p>Thread-safe: all configuration is immutable and per-call state lives in the execution's
 * {@link ExecutionAttributes}. One instance can serve any number of clients, sync or async — on the
 * async client the response leg runs on the Netty event loop, so read the README's Limitations
 * before pointing a high-concurrency async client at it.
 */
public final class PrismaAirsInterceptor implements ExecutionInterceptor {

    /** Default (US) Prisma AIRS API endpoint; override with PRISMA_AIRS_URL or {@link Builder#endpoint}. */
    public static final String DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com";

    private static final String SCAN_PATH = "/v1/scan/sync/request";

    // Repo convention: app_name identifies the integration, and users append their
    // own application name after it ("AWS-Bedrock-support-chat").
    private static final String APP_NAME_PREFIX = "AWS-Bedrock";

    private static final Logger LOGGER = Logger.getLogger("prisma_airs");

    // The JSON content-block walkers recurse (a tool_result carries content blocks of its own);
    // a body nested deeper than this is not a shape any model family uses, so it is treated as
    // unwalkable rather than followed down.
    private static final int MAX_CONTENT_DEPTH = 8;

    /** Per-execution scan state, carried between hooks in the SDK's ExecutionAttributes. */
    private static final ExecutionAttribute<ScanState> SCAN_STATE =
        new ExecutionAttribute<>("PrismaAirsScanState");

    /** What a block does to the caller. */
    public enum OnBlock {
        /** Throw {@link PrismaAirsBlockedException} (default). Works on both legs. */
        RAISE,
        /**
         * Response leg: replace the model output with a well-formed {@code CONTENT_FILTERED}
         * response instead of throwing. Prompt leg: {@code ExecutionInterceptor} has no seam that
         * can short-circuit the HTTP call with a synthetic response — throwing is the only abort
         * that prevents signing and transmission — so a blocked <em>prompt</em> still raises
         * {@link PrismaAirsBlockedException} even in this mode (see README, "Two blocking styles").
         */
        RESPOND
    }

    /** Fail posture when a scan cannot produce a usable verdict, or content cannot be extracted. */
    public enum Posture {
        BLOCK,
        ALLOW
    }

    private final String appName;
    private final String profileName;
    private final String profileId;
    private final String sessionId;
    private final String appUser;
    private final OnBlock onBlock;
    private final BiConsumer<String, JsonNode> onVerdict;
    private final Posture onError;
    private final Posture onUnscannable;
    private final boolean strictVerdict;
    private final boolean applyMaskedData;
    private final boolean scanPrompt;
    private final boolean scanResponse;
    private final Duration timeout;
    private final String endpointOverride;
    private final HttpClient httpClient;

    /**
     * All-defaults constructor, required by the SDK's classpath auto-discovery: a class listed in
     * {@code software/amazon/awssdk/global/handlers/execution.interceptors} is instantiated via its
     * default constructor. Configuration then comes entirely from the environment variables.
     */
    public PrismaAirsInterceptor() {
        this(builder());
    }

    private PrismaAirsInterceptor(Builder b) {
        this.appName = b.appName;
        this.profileName = b.profileName;
        this.profileId = b.profileId;
        this.sessionId = b.sessionId;
        this.appUser = b.appUser;
        this.onBlock = b.onBlock;
        this.onVerdict = b.onVerdict;
        this.onError = b.onError;
        this.onUnscannable = b.onUnscannable;
        this.strictVerdict = b.strictVerdict;
        this.applyMaskedData = b.applyMaskedData;
        this.scanPrompt = b.scanPrompt;
        this.scanResponse = b.scanResponse;
        this.timeout = b.timeout;
        this.endpointOverride = b.endpoint;
        // A redirect would re-send x-pan-token to whatever host the 3xx names; refuse.
        this.httpClient = HttpClient.newBuilder()
                                    .followRedirects(HttpClient.Redirect.NEVER)
                                    .connectTimeout(this.timeout)
                                    .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    // ----------------------------------------------------------------------
    // leg 1: before the request is marshalled, signed, or sent
    // ----------------------------------------------------------------------

    @Override
    public void beforeExecution(Context.BeforeExecution context, ExecutionAttributes executionAttributes) {
        SdkRequest request = context.request();
        String operation = operationOf(request);
        if (operation == null) {
            return; // not a Bedrock model invocation; stay out of the way
        }
        ScanState state = new ScanState(UUID.randomUUID().toString(), operation, modelIdOf(request));
        executionAttributes.putAttribute(SCAN_STATE, state);

        if (scanPrompt) {
            Extraction extraction = promptOf(request);
            if (extraction.opaque && onUnscannable == Posture.BLOCK) {
                // Documents, images, or video ride in this request; their content cannot be
                // inspected as text, so the fail-closed posture governs even when text is present.
                log(Level.WARNING, "prompt", "unscannable", state, 0.0, null, null,
                    "opaque multimodal content");
                throw blockedException("prompt", "unscannable", null, null, state, null);
            }
            String prompt = extraction.joined();
            if (isBlank(prompt)) {
                log(onUnscannable == Posture.BLOCK ? Level.WARNING : Level.INFO,
                    "prompt", "unscannable", state, 0.0, null, null, null);
                if (onUnscannable == Posture.BLOCK) {
                    throw blockedException("prompt", "unscannable", null, null, state, null);
                }
            } else {
                BlockVerdict block = runLeg("prompt", prompt, null, state).block;
                if (block != null) {
                    throw blockedException("prompt", block.category, block.scanId, block.reportId,
                                           state, block.rawJson);
                }
                state.prompt = prompt;
            }
        }

        if (scanResponse && isStreamingOperation(operation)) {
            // The streamed response is delivered as an event stream and never materializes as a
            // scannable object at this seam; record the skip so it is visible in the logs.
            log("response", "skipped-stream", state, 0.0, null, null);
        }
    }

    // ----------------------------------------------------------------------
    // leg 2: after the response is unmarshalled, before the caller sees it
    //
    // Runs only for successful HTTP responses -- the SDK routes error responses
    // through its error handler without invoking afterUnmarshalling/modifyResponse,
    // so AWS errors (throttle, auth failure, validation) pass through untouched.
    // ----------------------------------------------------------------------

    @Override
    public SdkResponse modifyResponse(Context.ModifyResponse context, ExecutionAttributes executionAttributes) {
        SdkResponse response = context.response();
        ScanState state = executionAttributes.getAttribute(SCAN_STATE);
        if (state == null || !scanResponse) {
            return response;
        }
        String text;
        String rawInvokeBody = null;
        if (response instanceof ConverseResponse converse) {
            text = textFromConverseResponse(converse);
        } else if (response instanceof InvokeModelResponse invoke) {
            rawInvokeBody = invoke.body() == null ? null : invoke.body().asUtf8String();
            text = textFromInvokeBody(rawInvokeBody);
        } else {
            return response; // streaming initial-response objects and anything else: not scannable here
        }

        if (isBlank(text)) {
            log(onUnscannable == Posture.BLOCK ? Level.WARNING : Level.INFO,
                "response", "unscannable", state, 0.0, null, null, null);
            if (onUnscannable == Posture.BLOCK) {
                return deliverResponseBlock(response, "unscannable", null, null, state, null);
            }
            return response;
        }

        LegOutcome outcome = runLeg("response", state.prompt, text, state);
        if (outcome.block != null) {
            return deliverResponseBlock(response, outcome.block.category, outcome.block.scanId,
                                        outcome.block.reportId, state, outcome.block.rawJson);
        }
        if (applyMaskedData && outcome.allowVerdict != null) {
            String masked = maskedData(outcome.allowVerdict);
            if (masked != null) {
                SdkResponse replaced = applyMask(response, masked);
                log("response", replaced != null ? "masked" : "mask-unappliable", state, 0.0, null, null);
                if (replaced == null) {
                    // Never deliver the unmasked original: fail closed like a response-leg block.
                    return deliverResponseBlock(response, "mask_unappliable", null, null, state, null);
                }
                return replaced;
            }
        }
        return response;
    }

    /** The masked text from a mask-and-allow DLP verdict, or {@code null} when absent. */
    private static String maskedData(JsonNode verdict) {
        Optional<JsonNode> node = verdict.field("response_masked_data");
        if (node.isEmpty() || !node.get().isObject()) {
            return null;
        }
        String data = stringField(node.get(), "data");
        return isBlank(data) ? null : data;
    }

    /**
     * Substitutes the masked text for the model output, preserving everything else about the
     * response. Returns {@code null} when the response shape cannot carry the substitution.
     */
    private static SdkResponse applyMask(SdkResponse response, String masked) {
        if (response instanceof ConverseResponse converse) {
            if (converse.output() == null || converse.output().message() == null) {
                return null;
            }
            Message message = converse.output().message();
            List<ContentBlock> substituted = substituteMaskedText(message.content(), masked);
            if (substituted == null) {
                return null;
            }
            Message replaced = message.toBuilder().content(substituted).build();
            return converse.toBuilder()
                           .output(ConverseOutput.builder().message(replaced).build())
                           .build();
        }
        if (response instanceof InvokeModelResponse invoke) {
            JsonWriter writer = JsonWriter.create();
            writer.writeStartObject();
            writer.writeFieldName("prisma_airs").writeValue("response masked");
            writer.writeFieldName("text").writeValue(masked);
            writer.writeEndObject();
            return invoke.toBuilder()
                         .contentType("application/json")
                         .body(SdkBytes.fromByteArray(writer.getBytes()))
                         .build();
        }
        return null;
    }

    /**
     * Puts the masked text in the FIRST text block and blanks the others, leaving every non-text
     * block where it was: collapsing the list to one text block would delete a toolUse block from
     * a benign, AIRS-allowed turn and strand the agent loop with nothing to call. Returns
     * {@code null} when no text block can carry the substitution, so the caller falls through to
     * the mask-unappliable withhold path rather than delivering the unmasked original. Masking
     * never rewrites stopReason.
     */
    private static List<ContentBlock> substituteMaskedText(List<ContentBlock> content, String masked) {
        if (content == null || content.isEmpty()) {
            return null;
        }
        List<ContentBlock> substituted = new ArrayList<>(content.size());
        boolean placed = false;
        for (ContentBlock block : content) {
            if (block != null && block.text() != null) {
                substituted.add(ContentBlock.fromText(placed ? "" : masked));
                placed = true;
            } else {
                substituted.add(block);
            }
        }
        return placed ? substituted : null;
    }

    // ----------------------------------------------------------------------
    // leg 2 delivery for RAISE mode: afterExecution sits OUTSIDE the SDK's retry
    // loop and response handler, so an exception thrown here is never retried and
    // reaches the sync caller unwrapped. The async pipeline routes it through
    // ThrowableUtils.asSdkException, which is why PrismaAirsBlockedException extends
    // SdkClientException -- it is then returned unchanged (seam-notes.md, section (b)).
    // ----------------------------------------------------------------------

    @Override
    public void afterExecution(Context.AfterExecution context, ExecutionAttributes executionAttributes) {
        ScanState state = executionAttributes.getAttribute(SCAN_STATE);
        if (state != null && state.pendingBlock != null) {
            PrismaAirsBlockedException blocked = state.pendingBlock;
            state.pendingBlock = null;
            throw blocked;
        }
    }

    // ----------------------------------------------------------------------
    // operation detection and text extraction
    // ----------------------------------------------------------------------

    private static String operationOf(SdkRequest request) {
        if (request instanceof ConverseRequest) {
            return "Converse";
        }
        if (request instanceof ConverseStreamRequest) {
            return "ConverseStream";
        }
        if (request instanceof InvokeModelRequest) {
            return "InvokeModel";
        }
        if (request instanceof InvokeModelWithResponseStreamRequest) {
            return "InvokeModelWithResponseStream";
        }
        return null;
    }

    private static boolean isStreamingOperation(String operation) {
        return "ConverseStream".equals(operation) || "InvokeModelWithResponseStream".equals(operation);
    }

    private static String modelIdOf(SdkRequest request) {
        if (request instanceof ConverseRequest r) {
            return r.modelId();
        }
        if (request instanceof ConverseStreamRequest r) {
            return r.modelId();
        }
        if (request instanceof InvokeModelRequest r) {
            return r.modelId();
        }
        if (request instanceof InvokeModelWithResponseStreamRequest r) {
            return r.modelId();
        }
        return null;
    }

    /**
     * Everything scannable a content-block list carries, and whether any block holds payloads that
     * cannot be inspected as text -- documents, images, video, audio, redacted reasoning, and any
     * block shape the walker does not recognize. Mirrors the boto3 sibling's
     * {@code (texts, opaque)} tuple.
     */
    private static final class Extraction {
        final List<String> texts = new ArrayList<>();
        boolean opaque;
        private int depth;

        void add(String text) {
            if (text != null) {
                texts.add(text);
            }
        }

        String joined() {
            return texts.isEmpty() ? null : String.join("\n", texts);
        }

        /** Enters one nesting level, or refuses and flags opaque once MAX_CONTENT_DEPTH is hit. */
        boolean descend() {
            if (depth >= MAX_CONTENT_DEPTH) {
                opaque = true;
                return false;
            }
            depth++;
            return true;
        }

        void ascend() {
            depth--;
        }
    }

    private static Extraction promptOf(SdkRequest request) {
        if (request instanceof ConverseRequest r) {
            return promptFromConverse(r.system(), r.messages());
        }
        if (request instanceof ConverseStreamRequest r) {
            return promptFromConverse(r.system(), r.messages());
        }
        if (request instanceof InvokeModelRequest r) {
            return promptFromInvokeBody(r.body());
        }
        if (request instanceof InvokeModelWithResponseStreamRequest r) {
            return promptFromInvokeBody(r.body());
        }
        return new Extraction();
    }

    /**
     * The system prompt plus EVERY user-role message, not just the newest one — a single call
     * can smuggle instructions in any of them. Assistant-role turns and {@code toolConfig} tool
     * specs are not walked (see README Limitations).
     */
    private static Extraction promptFromConverse(List<SystemContentBlock> system, List<Message> messages) {
        Extraction extraction = new Extraction();
        for (SystemContentBlock block : system == null ? List.<SystemContentBlock>of() : system) {
            if (block == null) {
                continue;
            }
            if (block.text() != null) {
                extraction.add(block.text());
            } else if (block.guardContent() != null) {
                absorbGuardContent(block.guardContent(), extraction);
            } else if (block.cachePoint() == null) {
                extraction.opaque = true; // an unrecognized system block, not an absence of content
            }
        }
        for (Message message : messages == null ? List.<Message>of() : messages) {
            if (message == null || message.role() != ConversationRole.USER) {
                continue;
            }
            absorbContentBlocks(message.content(), extraction);
        }
        return extraction;
    }

    /**
     * Every content block a message carries, as an ALLOWLIST with a fail-closed default: known
     * text-bearing shapes are extracted, known binary shapes flag opaque, and anything the walker
     * does not recognize -- a block type this SDK version does not model, or one Bedrock adds
     * later -- flags opaque too, so new content can never pass through unseen.
     */
    private static void absorbContentBlocks(List<ContentBlock> content, Extraction extraction) {
        for (ContentBlock block : content == null ? List.<ContentBlock>of() : content) {
            if (block == null) {
                continue;
            }
            if (block.text() != null) {
                extraction.add(block.text());
            } else if (block.guardContent() != null) {
                absorbGuardContent(block.guardContent(), extraction);
            } else if (block.toolUse() != null) {
                // The arguments the application is about to execute -- an exfiltration channel when
                // the model emits them. Name plus serialized input, as toolResult.json already is.
                extraction.add(block.toolUse().name());
                if (block.toolUse().input() != null) {
                    extraction.add(String.valueOf(block.toolUse().input()));
                }
            } else if (block.toolResult() != null) {
                absorbToolResultContent(block.toolResult().content(), extraction);
            } else if (block.reasoningContent() != null) {
                if (block.reasoningContent().reasoningText() != null) {
                    extraction.add(block.reasoningContent().reasoningText().text());
                } else {
                    extraction.opaque = true; // redactedContent: encrypted, not inspectable
                }
            } else if (block.searchResult() != null) {
                absorbSearchResult(block.searchResult(), extraction);
            } else if (block.citationsContent() != null) {
                absorbCitationsContent(block.citationsContent(), extraction);
            } else if (block.cachePoint() != null) {
                // A prompt-cache boundary marker: no model-visible content to scan or to withhold.
                continue;
            } else {
                // document / image / video / audio, and every shape this walker does not know.
                extraction.opaque = true;
            }
        }
    }

    /** guardContent carries either text or an image; the image is opaque like any other image. */
    private static void absorbGuardContent(GuardrailConverseContentBlock guard, Extraction extraction) {
        if (guard.text() != null) {
            extraction.add(guard.text().text());
        } else {
            extraction.opaque = true;
        }
    }

    /** ToolResultContentBlock members. This union has no audio member -- do not add one. */
    private static void absorbToolResultContent(List<ToolResultContentBlock> subBlocks, Extraction extraction) {
        for (ToolResultContentBlock sub : subBlocks == null ? List.<ToolResultContentBlock>of() : subBlocks) {
            if (sub == null) {
                continue;
            }
            if (sub.text() != null) {
                extraction.add(sub.text());
            } else if (sub.json() != null) {
                extraction.add(String.valueOf(sub.json()));
            } else if (sub.searchResult() != null) {
                absorbSearchResult(sub.searchResult(), extraction);
            } else {
                extraction.opaque = true; // document / image / video, and anything unrecognized
            }
        }
    }

    /** Retrieved passages -- the canonical indirect-injection carrier, so their text is scanned. */
    private static void absorbSearchResult(SearchResultBlock result, Extraction extraction) {
        List<SearchResultContentBlock> content = result.content();
        for (SearchResultContentBlock sub : content == null ? List.<SearchResultContentBlock>of() : content) {
            if (sub != null) {
                extraction.add(sub.text());
            }
        }
    }

    /** A citations block holds the model's generated answer plus the source text it cited. */
    private static void absorbCitationsContent(CitationsContentBlock citations, Extraction extraction) {
        List<CitationGeneratedContent> generated = citations.content();
        for (CitationGeneratedContent part : generated == null ? List.<CitationGeneratedContent>of() : generated) {
            if (part != null) {
                extraction.add(part.text());
            }
        }
        List<Citation> cited = citations.citations();
        for (Citation citation : cited == null ? List.<Citation>of() : cited) {
            if (citation == null) {
                continue;
            }
            List<CitationSourceContent> sources = citation.sourceContent();
            for (CitationSourceContent source : sources == null ? List.<CitationSourceContent>of() : sources) {
                if (source != null) {
                    extraction.add(source.text());
                }
            }
        }
    }

    /**
     * Model families speak different body dialects through InvokeModel. Known families get precise
     * extraction; anything unknown falls back to scanning the entire serialized body, which errs
     * toward inspecting too much rather than too little.
     */
    private static Extraction promptFromInvokeBody(SdkBytes body) {
        Extraction extraction = new Extraction();
        String raw = body == null ? null : body.asUtf8String();
        if (isBlank(raw)) {
            return extraction;
        }
        JsonNode parsed = tryParseJson(raw);
        if (parsed != null && parsed.isObject()) {
            Optional<JsonNode> messages = parsed.field("messages");
            if (messages.isPresent() && messages.get().isArray()) {   // messages dialect (incl. Amazon Nova)
                Extraction fromMessages = promptFromConverseJson(parsed);
                if (fromMessages.joined() != null || fromMessages.opaque) {
                    return fromMessages;
                }
            }
            for (String key : new String[] {"inputText", "prompt", "message"}) {  // titan / llama, mistral / cohere
                String value = stringField(parsed, key);
                if (!isBlank(value)) {
                    extraction.add(value);
                    if ("message".equals(key)) {
                        absorbChatHistory(parsed, extraction);
                    }
                    return extraction;
                }
            }
        }
        extraction.add(raw); // unknown dialect: scan everything
        return extraction;
    }

    /**
     * The rest of a {@code message}-keyed body: only the newest turn rides in {@code message}
     * itself, while the turn history, the grounding documents, and the tool results it carries
     * reach the model just as directly.
     */
    private static void absorbChatHistory(JsonNode bodyObject, Extraction extraction) {
        Optional<JsonNode> history = bodyObject.field("chat_history");
        if (history.isPresent() && history.get().isArray()) {
            for (JsonNode turn : history.get().asArray()) {
                if (turn != null && turn.isObject()) {
                    extraction.add(stringField(turn, "message"));
                }
            }
        }
        for (String key : new String[] {"documents", "tool_results"}) {
            Optional<JsonNode> node = bodyObject.field(key);
            if (node.isPresent() && node.get().isArray() && !node.get().asArray().isEmpty()) {
                extraction.add(node.get().toString());
            }
        }
    }

    /** The JSON twin of {@link #promptFromConverse}: top-level "system" plus every user message. */
    private static Extraction promptFromConverseJson(JsonNode bodyObject) {
        Extraction extraction = new Extraction();
        Optional<JsonNode> system = bodyObject.field("system");
        if (system.isPresent()) {
            absorbJsonMessageContent(system.get(), extraction);
        }
        Optional<JsonNode> messages = bodyObject.field("messages");
        if (messages.isPresent() && messages.get().isArray()) {
            for (JsonNode message : messages.get().asArray()) {
                if (message == null || !message.isObject()
                        || !"user".equals(stringField(message, "role"))) {
                    continue;
                }
                Optional<JsonNode> content = message.field("content");
                if (content.isPresent()) {
                    absorbJsonMessageContent(content.get(), extraction);
                }
            }
        }
        return extraction;
    }

    /** A "system" or "content" value: a bare string, a block array, or a shape we do not model. */
    private static void absorbJsonMessageContent(JsonNode value, Extraction extraction) {
        if (value.isString()) {
            if (!isBlank(value.asString())) {
                extraction.add(value.asString());
            }
        } else if (value.isArray()) {
            absorbJsonContentBlocks(value.asArray(), extraction);
        } else if (!value.isNull()) {
            extraction.opaque = true;
        }
    }

    /**
     * The JSON twin of {@link #absorbContentBlocks}, over the two content-block dialects InvokeModel
     * bodies use: the Converse-shaped one, discriminated by KEY ({@code {"text": ...}}), and the
     * messages dialect, discriminated by a {@code "type"} tag ({@code {"type":"tool_result", ...}}).
     * Same allowlist rule as the typed walker: an unrecognized block flags opaque, never vanishes.
     */
    private static void absorbJsonContentBlocks(List<JsonNode> blocks, Extraction extraction) {
        if (!extraction.descend()) {
            return;
        }
        for (JsonNode block : blocks) {
            if (block != null && block.isString()) {
                extraction.add(block.asString());
                continue;
            }
            if (block == null || !block.isObject()) {
                extraction.opaque = true;
                continue;
            }
            String text = stringField(block, "text");
            if (text != null) {                        // {"text": ...} and {"type":"text","text": ...}
                extraction.add(text);
                continue;
            }
            if (absorbJsonConverseBlock(block, extraction) || absorbJsonTypedBlock(block, extraction)) {
                continue;
            }
            extraction.opaque = true;
        }
        extraction.ascend();
    }

    /**
     * Converse-shaped JSON blocks, discriminated by key. Returns false when no key matched, so the
     * caller can try the type-tagged dialect.
     */
    private static boolean absorbJsonConverseBlock(JsonNode block, Extraction extraction) {
        Optional<JsonNode> guard = block.field("guardContent");
        if (guard.isPresent()) {
            Optional<JsonNode> guardText = guard.get().isObject()
                ? guard.get().field("text") : Optional.empty();
            String value = guardText.isPresent() && guardText.get().isObject()
                ? stringField(guardText.get(), "text") : null;
            if (value != null) {
                extraction.add(value);
            } else {
                extraction.opaque = true;              // guardContent carrying an image
            }
            return true;
        }
        Optional<JsonNode> toolUse = block.field("toolUse");
        if (toolUse.isPresent()) {
            absorbJsonToolUse(toolUse.get(), extraction);
            return true;
        }
        Optional<JsonNode> toolResult = block.field("toolResult");
        if (toolResult.isPresent()) {
            absorbJsonToolResultContent(toolResult.get().isObject()
                                        ? toolResult.get().field("content") : Optional.empty(), extraction);
            return true;
        }
        Optional<JsonNode> reasoning = block.field("reasoningContent");
        if (reasoning.isPresent()) {
            Optional<JsonNode> reasoningText = reasoning.get().isObject()
                ? reasoning.get().field("reasoningText") : Optional.empty();
            String value = reasoningText.isPresent() && reasoningText.get().isObject()
                ? stringField(reasoningText.get(), "text") : null;
            if (value != null) {
                extraction.add(value);
            } else {
                extraction.opaque = true;              // redactedContent
            }
            return true;
        }
        Optional<JsonNode> searchResult = block.field("searchResult");
        if (searchResult.isPresent()) {
            if (!absorbJsonTextArray(searchResult.get().isObject()
                                     ? searchResult.get().field("content") : Optional.empty(), extraction)) {
                extraction.opaque = true;
            }
            return true;
        }
        Optional<JsonNode> citations = block.field("citationsContent");
        if (citations.isPresent()) {
            absorbJsonCitations(citations.get(), extraction);
            return true;
        }
        Optional<JsonNode> json = block.field("json");
        if (json.isPresent()) {                        // a toolResult json member
            extraction.add(json.get().toString());
            return true;
        }
        if (block.field("cachePoint").isPresent()) {
            return true;                               // a cache boundary marker: nothing to scan
        }
        if (block.field("document").isPresent() || block.field("image").isPresent()
                || block.field("video").isPresent() || block.field("audio").isPresent()) {
            extraction.opaque = true;
            return true;
        }
        return false;
    }

    /**
     * Messages-dialect blocks, discriminated by {@code "type"}. Returns false when the block carries
     * no {@code "type"} tag at all, so the caller can fail it closed.
     */
    private static boolean absorbJsonTypedBlock(JsonNode block, Extraction extraction) {
        String type = stringField(block, "type");
        if (type == null) {
            return false;
        }
        switch (type) {
            case "tool_use":
                absorbJsonToolUse(block, extraction);
                return true;
            case "tool_result":
                // The content an attacker-controlled tool returned; a string or a nested block list.
                Optional<JsonNode> content = block.field("content");
                if (content.isPresent()) {
                    absorbJsonMessageContent(content.get(), extraction);
                } else {
                    extraction.opaque = true;
                }
                return true;
            case "thinking":
                String thinking = stringField(block, "thinking");
                if (thinking != null) {
                    extraction.add(thinking);
                } else {
                    extraction.opaque = true;
                }
                return true;
            default:
                // redacted_thinking, image, document, and every type this walker does not know.
                extraction.opaque = true;
                return true;
        }
    }

    /** Tool-call arguments in either dialect: the name plus the serialized input. */
    private static void absorbJsonToolUse(JsonNode toolUse, Extraction extraction) {
        if (!toolUse.isObject()) {
            extraction.opaque = true;
            return;
        }
        extraction.add(stringField(toolUse, "name"));
        Optional<JsonNode> input = toolUse.field("input");
        if (input.isPresent()) {
            extraction.add(input.get().toString());
        }
    }

    /** The JSON twin of {@link #absorbToolResultContent} -- the same allowlist, one level down. */
    private static void absorbJsonToolResultContent(Optional<JsonNode> content, Extraction extraction) {
        if (content.isEmpty() || !content.get().isArray()) {
            extraction.opaque = true;
            return;
        }
        absorbJsonContentBlocks(content.get().asArray(), extraction);
    }

    /**
     * Every {@code text} member of a block array, for searchResult and citation source content.
     * Reports whether the field was actually there as an array, so the caller can fail closed.
     */
    private static boolean absorbJsonTextArray(Optional<JsonNode> blocks, Extraction extraction) {
        if (blocks.isEmpty() || !blocks.get().isArray()) {
            return false;
        }
        for (JsonNode sub : blocks.get().asArray()) {
            if (sub != null && sub.isObject()) {
                extraction.add(stringField(sub, "text"));
            }
        }
        return true;
    }

    /** The model's generated answer plus the source text it cited. */
    private static void absorbJsonCitations(JsonNode citations, Extraction extraction) {
        if (!citations.isObject()) {
            extraction.opaque = true;
            return;
        }
        boolean walked = absorbJsonTextArray(citations.field("content"), extraction);
        Optional<JsonNode> cited = citations.field("citations");
        if (cited.isPresent() && cited.get().isArray()) {
            for (JsonNode citation : cited.get().asArray()) {
                if (citation != null && citation.isObject()) {
                    walked |= absorbJsonTextArray(citation.field("sourceContent"), extraction);
                }
            }
        }
        if (!walked) {
            extraction.opaque = true;
        }
    }

    private static String textFromConverseResponse(ConverseResponse response) {
        ConverseOutput output = response.output();
        if (output == null || output.message() == null) {
            return null;
        }
        Extraction extraction = new Extraction();
        absorbContentBlocks(output.message().content(), extraction);
        return extraction.joined();
    }

    private static String joinJsonContentTexts(List<JsonNode> blocks) {
        Extraction extraction = new Extraction();
        absorbJsonContentBlocks(blocks, extraction);
        return extraction.joined();
    }

    private static String textFromInvokeBody(String raw) {
        if (isBlank(raw)) {
            return null;
        }
        JsonNode parsed = tryParseJson(raw);
        if (parsed != null && parsed.isObject()) {
            Optional<JsonNode> content = parsed.field("content");          // messages-dialect responses
            if (content.isPresent() && content.get().isArray()) {
                String text = joinJsonContentTexts(content.get().asArray());
                if (!isBlank(text)) {
                    return text;
                }
            }
            Optional<JsonNode> output = parsed.field("output");            // nova
            if (output.isPresent() && output.get().isObject()) {
                Optional<JsonNode> message = output.get().field("message");
                if (message.isPresent() && message.get().isObject()) {
                    Optional<JsonNode> msgContent = message.get().field("content");
                    if (msgContent.isPresent() && msgContent.get().isArray()) {
                        String text = joinJsonContentTexts(msgContent.get().asArray());
                        if (!isBlank(text)) {
                            return text;
                        }
                    }
                }
            }
            Optional<JsonNode> results = parsed.field("results");          // titan
            if (results.isPresent() && results.get().isArray() && !results.get().asArray().isEmpty()) {
                JsonNode first = results.get().asArray().get(0);
                if (first.isObject()) {
                    String text = stringField(first, "outputText");
                    if (!isBlank(text)) {
                        return text;
                    }
                }
            }
            for (String key : new String[] {"generation", "outputs", "text", "completion"}) {  // llama / mistral / cohere
                Optional<JsonNode> value = parsed.field(key);
                if (value.isEmpty()) {
                    continue;
                }
                if (value.get().isString() && !isBlank(value.get().asString())) {
                    return value.get().asString();
                }
                if (value.get().isArray() && !value.get().asArray().isEmpty()) {
                    JsonNode first = value.get().asArray().get(0);
                    if (first.isObject()) {
                        String text = stringField(first, "text");
                        if (!isBlank(text)) {
                            return text;
                        }
                    }
                }
            }
        }
        return raw; // fall back to scanning the whole body
    }

    // ----------------------------------------------------------------------
    // block delivery
    // ----------------------------------------------------------------------

    private PrismaAirsBlockedException blockedException(String leg, String category, String scanId,
                                                        String reportId, ScanState state, String rawJson) {
        return new PrismaAirsBlockedException(leg, category, scanId, reportId,
                                              state.transactionId, state.operation, rawJson);
    }

    /**
     * modifyResponse cannot short-circuit; it blocks either by substituting a shaped response
     * (RESPOND) or by arming afterExecution to throw (RAISE — the exception then reaches the caller
     * as the declared type, outside the retry loop and the response handler's exception wrapping).
     */
    private SdkResponse deliverResponseBlock(SdkResponse response, String category, String scanId,
                                             String reportId, ScanState state, String rawJson) {
        if (onBlock == OnBlock.RAISE) {
            state.pendingBlock = blockedException("response", category, scanId, reportId, state, rawJson);
            return response; // discarded: afterExecution throws before the caller sees it
        }
        String message = String.format(
            "The model response was withheld by Prisma AIRS (category=%s, scan_id=%s).", category, scanId);
        if (response instanceof ConverseResponse converse) {
            return converse.toBuilder()
                           .output(ConverseOutput.builder()
                                                 .message(Message.builder()
                                                                 .role(ConversationRole.ASSISTANT)
                                                                 .content(ContentBlock.fromText(message))
                                                                 .build())
                                                 .build())
                           .stopReason(StopReason.CONTENT_FILTERED)
                           .build();
        }
        InvokeModelResponse invoke = (InvokeModelResponse) response;
        JsonWriter writer = JsonWriter.create();
        writer.writeStartObject();
        writer.writeFieldName("prisma_airs_blocked").writeValue(true);
        writer.writeFieldName("message").writeValue(message);
        writer.writeEndObject();
        return invoke.toBuilder()
                     .contentType("application/json")
                     .body(SdkBytes.fromByteArray(writer.getBytes()))
                     .build();
    }

    // ----------------------------------------------------------------------
    // the scan call (same hardened client posture as the other AWS integrations)
    // ----------------------------------------------------------------------

    /**
     * Runs one scan leg. The outcome carries a {@link BlockVerdict} when the caller must block (a
     * genuine block verdict, or an error under the fail-closed posture), or the allow verdict so
     * the response leg can apply mask-and-allow DLP data.
     */
    private LegOutcome runLeg(String leg, String prompt, String responseText, ScanState state) {
        String apiKey = env("PRISMA_AIRS_API_KEY");
        String profile = profileName != null ? profileName : env("PRISMA_AIRS_PROFILE_NAME");
        String endpoint = endpointOverride != null ? endpointOverride
                          : Optional.ofNullable(env("PRISMA_AIRS_URL")).orElse(DEFAULT_ENDPOINT);

        if (isBlank(apiKey) || (isBlank(profile) && isBlank(profileId))) {
            String reason = "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set";
            log(leg, "error", state, 0.0, null, reason);
            return onError == Posture.BLOCK ? LegOutcome.blocked(BlockVerdict.error(reason))
                                            : LegOutcome.none();
        }

        byte[] payload = buildScanPayload(prompt, responseText, profile, state);
        long started = System.nanoTime();
        ScanResult result = scan(endpoint, apiKey, payload);
        double elapsedMs = (System.nanoTime() - started) / 1_000_000.0;

        String error = result.error;
        String action = null;
        JsonNode verdict = result.verdict;
        if (error == null) {
            Optional<JsonNode> actionNode = verdict.field("action");
            if (actionNode.isEmpty() || !actionNode.get().isString()) {
                error = "scan response carries no action verdict";
            } else {
                action = actionNode.get().asString().toLowerCase(Locale.ROOT);
                if (!"allow".equals(action) && !"block".equals(action)) {
                    error = "unknown scan action \"" + action + "\"";
                }
            }
        }
        if (error == null && strictVerdict && "allow".equals(action) && isDegraded(verdict)) {
            error = String.format("degraded scan under strictVerdict (timeout=%s error=%s)",
                                  flagged(verdict, "timeout"), flagged(verdict, "error"));
        }
        if (error != null) {
            log(leg, "error", state, elapsedMs, null, error);
            return onError == Posture.BLOCK ? LegOutcome.blocked(BlockVerdict.error(error))
                                            : LegOutcome.none();
        }

        log(leg, action, state, elapsedMs, verdict, null);
        if (onVerdict != null) {
            try {
                onVerdict.accept(leg, verdict);
            } catch (Exception exc) {
                warnCallbackFailed(exc);
            }
        }
        return "block".equals(action) ? LegOutcome.blocked(BlockVerdict.fromVerdict(verdict))
                                      : LegOutcome.allowed(verdict);
    }

    private byte[] buildScanPayload(String prompt, String responseText, String profile, ScanState state) {
        JsonWriter writer = JsonWriter.create();
        writer.writeStartObject();
        writer.writeFieldName("transaction_id").writeValue(state.transactionId);
        if (!isBlank(sessionId)) {
            writer.writeFieldName("session_id").writeValue(sessionId);
        }
        writer.writeFieldName("ai_profile");
        writer.writeStartObject();
        if (!isBlank(profileId)) {
            writer.writeFieldName("profile_id").writeValue(profileId);
        }
        if (!isBlank(profile)) {
            writer.writeFieldName("profile_name").writeValue(profile);
        }
        writer.writeEndObject();
        writer.writeFieldName("metadata");
        writer.writeStartObject();
        writer.writeFieldName("app_name")
              .writeValue(isBlank(appName) ? APP_NAME_PREFIX : APP_NAME_PREFIX + "-" + appName);
        if (!isBlank(appUser)) {
            writer.writeFieldName("app_user").writeValue(appUser);
        }
        if (state.modelId != null) {
            writer.writeFieldName("ai_model").writeValue(state.modelId);
        }
        writer.writeEndObject();
        writer.writeFieldName("contents");
        writer.writeStartArray();
        writer.writeStartObject();
        if (prompt != null) {
            writer.writeFieldName("prompt").writeValue(prompt);
        }
        if (responseText != null) {
            writer.writeFieldName("response").writeValue(responseText);
        }
        writer.writeEndObject();
        writer.writeEndArray();
        writer.writeEndObject();
        return writer.getBytes();
    }

    private ScanResult scan(String endpoint, String apiKey, byte[] payload) {
        if (!endpoint.toLowerCase(Locale.ROOT).startsWith("https://")) {
            return ScanResult.failure("refusing non-HTTPS endpoint: " + endpoint);
        }
        String url = endpoint.replaceAll("/+$", "") + SCAN_PATH;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                                             .timeout(timeout)
                                             .header("Content-Type", "application/json")
                                             .header("x-pan-token", apiKey)
                                             .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                                             .build();
            HttpResponse<String> response =
                httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                String body = response.body() == null ? "" : response.body();
                return ScanResult.failure("HTTP " + response.statusCode() + " from AIRS: "
                                          + body.substring(0, Math.min(body.length(), 500)));
            }
            JsonNode parsed = tryParseJson(response.body());
            if (parsed == null || !parsed.isObject()) {
                return ScanResult.failure("unexpected scan response shape");
            }
            return ScanResult.success(parsed);
        } catch (IOException exc) {
            return ScanResult.failure("network error reaching AIRS: " + exc);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            return ScanResult.failure("interrupted while scanning: " + exc);
        } catch (RuntimeException exc) {
            return ScanResult.failure("scan failed: " + exc);
        }
    }

    // ----------------------------------------------------------------------
    // verdict inspection and logging
    // ----------------------------------------------------------------------

    private static boolean isDegraded(JsonNode verdict) {
        String category = stringField(verdict, "category");
        String lowered = category == null ? "" : category.toLowerCase(Locale.ROOT);
        return flagged(verdict, "timeout") || flagged(verdict, "error")
               || "error".equals(lowered) || "timeout".equals(lowered);
    }

    /** Truthiness of a verdict field: boolean true, a non-empty string, or any other non-null value. */
    private static boolean flagged(JsonNode verdict, String field) {
        Optional<JsonNode> node = verdict.field(field);
        if (node.isEmpty() || node.get().isNull()) {
            return false;
        }
        if (node.get().isBoolean()) {
            return node.get().asBoolean();
        }
        if (node.get().isString()) {
            return !node.get().asString().isEmpty();
        }
        return true;
    }

    private static String stringField(JsonNode object, String field) {
        Optional<JsonNode> node = object.field(field);
        return node.isPresent() && node.get().isString() ? node.get().asString() : null;
    }

    /** Outcomes that are routine on healthy traffic; everything else logs at WARNING. */
    private static final Set<String> NEUTRAL_ACTIONS = Set.of("allow", "skipped-stream", "masked");

    /** One line of JSON per scan leg: INFO for allows and neutral outcomes, WARNING otherwise. */
    private static void log(String leg, String action, ScanState state, double elapsedMs,
                            JsonNode verdict, String error) {
        log(NEUTRAL_ACTIONS.contains(action) ? Level.INFO : Level.WARNING,
            leg, action, state, elapsedMs, verdict, error, null);
    }

    private static void log(Level level, String leg, String action, ScanState state, double elapsedMs,
                            JsonNode verdict, String error, String note) {
        JsonWriter writer = JsonWriter.create();
        writer.writeStartObject();
        writer.writeFieldName("leg").writeValue(leg);
        writer.writeFieldName("action").writeValue(action);
        writer.writeFieldName("transaction_id").writeValue(state.transactionId);
        writer.writeFieldName("ms").writeValue(Math.round(elapsedMs * 10.0) / 10.0);
        if (state.operation != null) {
            writer.writeFieldName("operation").writeValue(state.operation);
        }
        if (verdict != null) {
            String category = stringField(verdict, "category");
            if (category != null) {
                writer.writeFieldName("category").writeValue(category);
            }
            String scanId = stringField(verdict, "scan_id");
            if (scanId != null) {
                writer.writeFieldName("scan_id").writeValue(scanId);
            }
            String reportId = stringField(verdict, "report_id");
            if (reportId != null) {
                writer.writeFieldName("report_id").writeValue(reportId);
            }
            boolean wroteDetected = false;
            for (String side : new String[] {"prompt_detected", "response_detected"}) {
                List<String> hits = detectionHits(verdict, side);
                if (!hits.isEmpty()) {
                    if (!wroteDetected) {
                        writer.writeFieldName("detected");
                        writer.writeStartObject();
                        wroteDetected = true;
                    }
                    writer.writeFieldName(side);
                    writer.writeStartArray();
                    for (String hit : hits) {
                        writer.writeValue(hit);
                    }
                    writer.writeEndArray();
                }
            }
            if (wroteDetected) {
                writer.writeEndObject();
            }
            if (flagged(verdict, "timeout")) {
                writer.writeFieldName("timeout").writeValue(true);
            }
            if (flagged(verdict, "error")) {
                writer.writeFieldName("error_flag").writeValue(true);
            }
        }
        if (error != null) {
            writer.writeFieldName("error").writeValue(error);
        }
        if (note != null) {
            writer.writeFieldName("note").writeValue(note);
        }
        writer.writeEndObject();
        LOGGER.log(level, "prisma_airs " + new String(writer.getBytes(), StandardCharsets.UTF_8));
    }

    private static List<String> detectionHits(JsonNode verdict, String side) {
        List<String> hits = new ArrayList<>();
        Optional<JsonNode> node = verdict.field(side);
        if (node.isPresent() && node.get().isObject()) {
            for (Map.Entry<String, JsonNode> entry : node.get().asObject().entrySet()) {
                JsonNode value = entry.getValue();
                if (value != null && value.isBoolean() && value.asBoolean()) {
                    hits.add(entry.getKey());
                }
            }
        }
        return hits;
    }

    private static void warnCallbackFailed(Exception exc) {
        JsonWriter writer = JsonWriter.create();
        writer.writeStartObject();
        writer.writeFieldName("warning").writeValue("onVerdict callback failed");
        writer.writeFieldName("error").writeValue(String.valueOf(exc));
        writer.writeEndObject();
        LOGGER.warning("prisma_airs " + new String(writer.getBytes(), StandardCharsets.UTF_8));
    }

    // ----------------------------------------------------------------------
    // small helpers and helper types
    // ----------------------------------------------------------------------

    private static JsonNode tryParseJson(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return JsonNode.parser().parse(raw);
        } catch (RuntimeException exc) {
            return null;
        }
    }

    private static String env(String name) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? null : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Per-execution state carried between beforeExecution, modifyResponse, and afterExecution. */
    private static final class ScanState {
        final String transactionId;
        final String operation;
        final String modelId;
        volatile String prompt;
        volatile PrismaAirsBlockedException pendingBlock;

        ScanState(String transactionId, String operation, String modelId) {
            this.transactionId = transactionId;
            this.operation = operation;
            this.modelId = modelId;
        }
    }

    /** Why a leg must block: a genuine verdict, or a scan failure under the fail-closed posture. */
    private static final class BlockVerdict {
        final String category;
        final String scanId;
        final String reportId;
        final String rawJson;

        private BlockVerdict(String category, String scanId, String reportId, String rawJson) {
            this.category = category;
            this.scanId = scanId;
            this.reportId = reportId;
            this.rawJson = rawJson;
        }

        static BlockVerdict fromVerdict(JsonNode verdict) {
            return new BlockVerdict(stringField(verdict, "category"),
                                    stringField(verdict, "scan_id"),
                                    stringField(verdict, "report_id"),
                                    verdict.toString());
        }

        static BlockVerdict error(String reason) {
            JsonWriter writer = JsonWriter.create();
            writer.writeStartObject();
            writer.writeFieldName("action").writeValue("block");
            writer.writeFieldName("category").writeValue("airs_error");
            writer.writeFieldName("error").writeValue(reason);
            writer.writeEndObject();
            return new BlockVerdict("airs_error", null, null,
                                    new String(writer.getBytes(), StandardCharsets.UTF_8));
        }
    }

    /** What one scan leg decided: block (with why), allow (with the verdict), or stand aside. */
    private static final class LegOutcome {
        final BlockVerdict block;
        final JsonNode allowVerdict;

        private LegOutcome(BlockVerdict block, JsonNode allowVerdict) {
            this.block = block;
            this.allowVerdict = allowVerdict;
        }

        static LegOutcome blocked(BlockVerdict block) {
            return new LegOutcome(block, null);
        }

        static LegOutcome allowed(JsonNode verdict) {
            return new LegOutcome(null, verdict);
        }

        /** An error under onError=ALLOW: no block, but no verdict to apply masking from either. */
        static LegOutcome none() {
            return new LegOutcome(null, null);
        }
    }

    private static final class ScanResult {
        final JsonNode verdict;
        final String error;

        private ScanResult(JsonNode verdict, String error) {
            this.verdict = verdict;
            this.error = error;
        }

        static ScanResult success(JsonNode verdict) {
            return new ScanResult(verdict, null);
        }

        static ScanResult failure(String error) {
            return new ScanResult(null, error);
        }
    }

    // ----------------------------------------------------------------------
    // configuration
    // ----------------------------------------------------------------------

    /** Fluent configuration; every option has a safe default, so {@code builder().build()} works. */
    public static final class Builder {
        private String appName;
        private String profileName;
        private String profileId;
        private String sessionId;
        private String appUser;
        private OnBlock onBlock = OnBlock.RAISE;
        private BiConsumer<String, JsonNode> onVerdict;
        private Posture onError = Posture.BLOCK;
        private Posture onUnscannable = Posture.BLOCK;
        private boolean strictVerdict = false;
        private boolean applyMaskedData = false;
        private boolean scanPrompt = true;
        private boolean scanResponse = true;
        private Duration timeout = Duration.ofSeconds(10);
        private String endpoint;

        private Builder() {
        }

        /** Appended to the repo prefix: {@code metadata.app_name = "AWS-Bedrock-<appName>"}. */
        public Builder appName(String appName) {
            this.appName = appName;
            return this;
        }

        /** Overrides PRISMA_AIRS_PROFILE_NAME. */
        public Builder profileName(String profileName) {
            this.profileName = profileName;
            return this;
        }

        /** AI profile UUID; name or id must resolve. */
        public Builder profileId(String profileId) {
            this.profileId = profileId;
            return this;
        }

        /** Conversation id for Strata Cloud Manager session correlation. */
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /** End-user identity for {@code metadata.app_user}. */
        public Builder appUser(String appUser) {
            this.appUser = appUser;
            return this;
        }

        /** RAISE (default) or RESPOND — see {@link OnBlock} for the prompt-leg caveat. */
        public Builder onBlock(OnBlock onBlock) {
            this.onBlock = requireNonNull(onBlock, "onBlock");
            return this;
        }

        /** Observer invoked as {@code (leg, verdict)} for every scan verdict, allow or block. */
        public Builder onVerdict(BiConsumer<String, JsonNode> onVerdict) {
            this.onVerdict = onVerdict;
            return this;
        }

        /** BLOCK (default) or ALLOW when AIRS is unreachable or errors. */
        public Builder onError(Posture onError) {
            this.onError = requireNonNull(onError, "onError");
            return this;
        }

        /** BLOCK (default) or ALLOW when no text can be extracted from a request or response. */
        public Builder onUnscannable(Posture onUnscannable) {
            this.onUnscannable = requireNonNull(onUnscannable, "onUnscannable");
            return this;
        }

        /** Treat a detection-service timeout/error inside an allow verdict per the onError posture. */
        public Builder strictVerdict(boolean strictVerdict) {
            this.strictVerdict = strictVerdict;
            return this;
        }

        /**
         * On a response-leg allow verdict carrying {@code response_masked_data.data} (a
         * mask-and-allow DLP profile), the masked text replaces the response the caller receives.
         * If the substitution is not possible for a response shape, the call fails closed exactly
         * like a response-leg block — the unmasked original is never delivered. Default false.
         */
        public Builder applyMaskedData(boolean applyMaskedData) {
            this.applyMaskedData = applyMaskedData;
            return this;
        }

        public Builder scanPrompt(boolean scanPrompt) {
            this.scanPrompt = scanPrompt;
            return this;
        }

        public Builder scanResponse(boolean scanResponse) {
            this.scanResponse = scanResponse;
            return this;
        }

        /** Per-scan cap (two scans per round trip). Default 10 seconds. */
        public Builder timeout(Duration timeout) {
            if (timeout == null || timeout.isNegative() || timeout.isZero()) {
                throw new IllegalArgumentException("timeout must be positive");
            }
            this.timeout = timeout;
            return this;
        }

        /** Overrides PRISMA_AIRS_URL. HTTPS enforced, redirects refused. */
        public Builder endpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public PrismaAirsInterceptor build() {
            return new PrismaAirsInterceptor(this);
        }

        private static <T> T requireNonNull(T value, String name) {
            if (value == null) {
                throw new IllegalArgumentException(name + " must not be null");
            }
            return value;
        }
    }
}
