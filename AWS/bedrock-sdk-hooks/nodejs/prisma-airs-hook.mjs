/**
 * Prisma AIRS scan hook for the Amazon Bedrock JavaScript SDK (v3).
 *
 * Registers on the SDK's middleware stack so that EVERY Bedrock model
 * invocation sent through a protected client -- including calls a framework
 * makes on the application's behalf -- is scanned by Prisma AIRS:
 *
 *   on the way in    the outbound prompt is scanned; a blocked prompt never
 *                    leaves the process (the middleware chain is abandoned
 *                    before serialization, SigV4 signing, and any network
 *                    I/O -- nothing is sent, nothing is billed)
 *   on the way out   the model's response is scanned after deserialization,
 *                    before the caller's promise resolves; a blocked
 *                    response is withheld
 *
 * A Bedrock guardrail is a request parameter: every call site must remember
 * to pass it, and a call without it is silently unguarded. A middleware is
 * registered on the client itself and applies to every command sent through
 * it. Protecting the same client twice is a no-op, not a double scan.
 *
 * Single file, zero dependencies beyond the AWS SDK the application already
 * has (this module itself imports only node:crypto). Works with Converse,
 * ConverseStream, InvokeModel, and InvokeModelWithResponseStream.
 *
 * Environment variables (standard Prisma AIRS names):
 *
 *     PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
 *     PRISMA_AIRS_PROFILE_NAME   required   security profile name (or pass profileName)
 *     PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region
 *
 * Usage:
 *
 *     import { BedrockRuntimeClient } from "@aws-sdk/client-bedrock-runtime";
 *     import { protectClient } from "./prisma-airs-hook.mjs";
 *
 *     const bedrock = protectClient(new BedrockRuntimeClient({}), { appName: "support-chat" });
 *
 *     await bedrock.send(new ConverseCommand({ ... }));   // scanned, both directions
 */

import { randomUUID } from "node:crypto";

export const DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com";
const SCAN_PATH = "/v1/scan/sync/request";
// A verdict is a few kilobytes; the cap is the same one the sibling ports use.
const MAX_SCAN_BODY_BYTES = 10 * 1024 * 1024;

// Repo convention: app_name identifies the integration, and users append their
// own application name after it ("AWS-Bedrock-support-chat").
const APP_NAME_PREFIX = "AWS-Bedrock";

const HOOK_OPERATIONS = new Set([
  "Converse", "ConverseStream", "InvokeModel", "InvokeModelWithResponseStream",
]);
const STREAM_OPERATIONS = new Set(["ConverseStream", "InvokeModelWithResponseStream"]);

/**
 * One line per scan leg: allows and neutral outcomes (stream-response skips,
 * masking applied) go to stdout, blocks and errors to stderr. Set
 * `logger.level = "silent"` to silence everything, or "warn" to keep only
 * blocks and errors.
 */
export const logger = {
  level: "info", // "info" | "warn" | "silent"
  info(line) { if (this.level === "info") console.log(line); },
  warn(line) { if (this.level !== "silent") console.error(line); },
};

/** Thrown to the caller when a scan verdict blocks a model call. */
export class PrismaAirsBlocked extends Error {
  constructor(leg, verdict, transactionId, operation = null) {
    super(
      `blocked by Prisma AIRS on the ${leg} leg of ${operation || "a Bedrock call"} ` +
      `(category=${verdict?.category} scan_id=${verdict?.scan_id} transaction_id=${transactionId})`,
    );
    this.name = "PrismaAirsBlocked";
    this.leg = leg;
    this.verdict = verdict;
    this.transactionId = transactionId;
    this.operation = operation;
  }
}

// --------------------------------------------------------------------------
// prompt / response extraction per Bedrock operation
// --------------------------------------------------------------------------

/**
 * {texts, opaque}: every scannable string in a content-block list, and
 * whether any block carries payloads that cannot be inspected as text.
 *
 * An allowlist, deliberately. The known text-bearing shapes are extracted and
 * everything else -- documents, images, video, audio, and any block type
 * Bedrock adds after this file was written -- sets `opaque`, so the
 * onUnscannable posture governs instead of the content quietly vanishing from
 * the scan while the leg still reports a clean allow.
 *
 * Two dialects arrive here. Converse blocks are discriminated by their key
 * ({text: "..."}); the messages dialect several families accept through
 * InvokeModel is discriminated by a `type` member ({type: "text", text: "..."})
 * and is walked by textsFromTypedBlock.
 */
function textsFromConverseContent(content) {
  const texts = [];
  let opaque = false;
  for (const block of Array.isArray(content) ? content : []) {
    if (!block || typeof block !== "object") {
      opaque = true;
      continue;
    }
    if (typeof block.type === "string") {
      const walked = textsFromTypedBlock(block);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
      continue;
    }
    if (typeof block.text === "string") {
      texts.push(block.text);
    } else if ("guardContent" in block) {
      const guard = block.guardContent;
      const text = guard?.text?.text;
      if (typeof text === "string") texts.push(text);
      // guardContent also carries images, which are not text.
      const members = guard && typeof guard === "object" ? Object.keys(guard) : [];
      if (typeof text !== "string" || members.some((key) => key !== "text")) opaque = true;
    } else if ("cachePoint" in block) {
      // A prompt-caching marker (its only members are type and ttl): it
      // carries no content of its own, so there is nothing to scan here and
      // nothing hiding from the scan either.
      const marker = block.cachePoint;
      const members = marker && typeof marker === "object" ? Object.keys(marker) : [];
      if (!members.length || members.some((key) => key !== "type" && key !== "ttl")) opaque = true;
    } else if ("toolUse" in block) {
      const call = textsFromToolCall(block.toolUse);
      texts.push(...call.texts);
      opaque = opaque || call.opaque;
    } else if ("toolResult" in block) {
      const walked = textsFromToolResultContent(block.toolResult?.content);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
    } else if ("reasoningContent" in block) {
      const reasoning = block.reasoningContent;
      const text = reasoning?.reasoningText?.text;
      if (typeof text === "string") texts.push(text);
      // redactedContent is ciphertext the SDK cannot read as text.
      const redacted = reasoning && typeof reasoning === "object" && "redactedContent" in reasoning;
      if (typeof text !== "string" || redacted) opaque = true;
    } else if ("searchResult" in block) {
      // RAG passages: the canonical indirect-prompt-injection carrier.
      const walked = textsFromSearchResult(block.searchResult);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
    } else if ("citationsContent" in block) {
      const walked = textsFromCitations(block.citationsContent);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
    } else {
      opaque = true;   // document, image, video, audio, anything newer
    }
  }
  return { texts, opaque };
}

/**
 * {texts, opaque} for one block of the messages dialect. Tagged by `type`
 * rather than by key, so it needs its own table; same allowlist discipline.
 */
function textsFromTypedBlock(block) {
  const texts = [];
  let opaque = false;
  if (block.type === "text" || block.type === "thinking") {
    const text = block.type === "text" ? block.text : block.thinking;
    if (typeof text === "string") texts.push(text);
    else opaque = true;
  } else if (block.type === "tool_use") {
    const call = textsFromToolCall(block);
    texts.push(...call.texts);
    opaque = call.opaque;
  } else if (block.type === "tool_result") {
    const content = block.content;
    if (typeof content === "string") {
      texts.push(content);
    } else if (Array.isArray(content)) {
      const walked = textsFromConverseContent(content);
      texts.push(...walked.texts);
      opaque = walked.opaque;
    } else {
      opaque = true;
    }
  } else {
    opaque = true;   // image, document, redacted_thinking, anything newer
  }
  return { texts, opaque };
}

/**
 * {texts, opaque} for one tool call: the tool name and its serialized
 * arguments. Model-emitted tool arguments are an exfiltration channel, so
 * they are scanned exactly as toolResult json payloads already are.
 */
function textsFromToolCall(call) {
  if (!call || typeof call !== "object") return { texts: [], opaque: true };
  const texts = [];
  if (typeof call.name === "string" && call.name) texts.push(call.name);
  const args = jsonText(call.input);
  if (args == null) return { texts, opaque: true };
  texts.push(args);
  return { texts, opaque: false };
}

/**
 * {texts, opaque} for the members of a Converse toolResult block: text and
 * json are scannable, searchResult recurses, and documents, images, video or
 * anything unrecognized are opaque.
 */
function textsFromToolResultContent(content) {
  const texts = [];
  let opaque = !Array.isArray(content);
  for (const sub of Array.isArray(content) ? content : []) {
    if (!sub || typeof sub !== "object") {
      opaque = true;
    } else if (typeof sub.text === "string") {
      texts.push(sub.text);
    } else if ("json" in sub) {
      const serialized = jsonText(sub.json);
      if (serialized == null) opaque = true;
      else texts.push(serialized);
    } else if ("searchResult" in sub) {
      const walked = textsFromSearchResult(sub.searchResult);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
    } else {
      opaque = true;
    }
  }
  return { texts, opaque };
}

/** {texts, opaque} for the passages inside a searchResult block. */
function textsFromSearchResult(searchResult) {
  const content = searchResult?.content;
  if (!Array.isArray(content)) return { texts: [], opaque: true };
  return textsFromConverseContent(content);
}

/**
 * {texts, opaque} for a citationsContent block: the answer the model
 * generated, plus the source passages it cites.
 */
function textsFromCitations(citationsContent) {
  const generated = citationsContent?.content;
  const citations = citationsContent?.citations;
  if (!Array.isArray(generated) && !Array.isArray(citations)) {
    return { texts: [], opaque: true };
  }
  const texts = [];
  let opaque = false;
  if (Array.isArray(generated)) {
    const walked = textsFromConverseContent(generated);
    texts.push(...walked.texts);
    opaque = walked.opaque;
  }
  for (const citation of Array.isArray(citations) ? citations : []) {
    if (!Array.isArray(citation?.sourceContent)) {
      opaque = true;
      continue;
    }
    const walked = textsFromConverseContent(citation.sourceContent);
    texts.push(...walked.texts);
    opaque = opaque || walked.opaque;
  }
  return { texts, opaque };
}

/**
 * JSON text for a tool argument or a tool result payload. A value even the
 * SDK could not serialize (circular, BigInt) cannot be scanned as text; null
 * tells the caller to flag the block opaque rather than scan nothing.
 */
function jsonText(value) {
  try {
    const text = JSON.stringify(value ?? null);
    return typeof text === "string" ? text : null;
  } catch {
    return null;
  }
}

/**
 * {prompt, opaque}: the system prompt and every user-role message -- not just
 * the newest one, since a single call can smuggle instructions in any of them.
 */
function promptFromConverseBody(body) {
  const texts = [];
  let opaque = false;
  const system = body?.system;
  if (typeof system === "string" && system.trim()) {
    texts.push(system);
  } else if (Array.isArray(system)) {
    const walked = textsFromConverseContent(system);
    texts.push(...walked.texts);
    opaque = opaque || walked.opaque;
  }
  for (const message of Array.isArray(body?.messages) ? body.messages : []) {
    if (message?.role !== "user") continue;
    const content = message.content;
    if (typeof content === "string" && content.trim()) {
      texts.push(content);
    } else {
      const walked = textsFromConverseContent(content);
      texts.push(...walked.texts);
      opaque = opaque || walked.opaque;
    }
  }
  return { prompt: texts.length ? texts.join("\n") : null, opaque };
}

// Model families speak different body dialects through InvokeModel. Known
// families get precise extraction; anything unknown falls back to scanning the
// entire serialized body, which errs toward inspecting too much rather than
// too little.
function promptFromInvokeBody(body) {
  if (Array.isArray(body.messages)) {              // messages-style chat bodies (incl. Amazon Nova)
    const { prompt, opaque } = promptFromConverseBody(body);
    if (prompt || opaque) return { prompt, opaque };
  }
  for (const key of ["inputText", "prompt"]) {     // titan / llama, mistral
    if (typeof body[key] === "string" && body[key].trim()) {
      return { prompt: body[key], opaque: false };
    }
  }
  if (typeof body.message === "string" && body.message.trim()) {   // cohere chat
    return promptFromCohereBody(body);
  }
  return { prompt: null, opaque: false };
}

// Cohere Chat carries the newest turn in `message` and everything else beside
// it: the conversation history, the grounding documents, and the results of
// earlier tool calls. All of it reaches the model, so all of it is scanned.
function promptFromCohereBody(body) {
  const texts = [body.message];
  let opaque = false;
  for (const turn of Array.isArray(body.chat_history) ? body.chat_history : []) {
    if (typeof turn?.message === "string" && turn.message.trim()) texts.push(turn.message);
  }
  for (const key of ["documents", "tool_results"]) {
    const value = body[key];
    if (!Array.isArray(value) || !value.length) continue;
    const serialized = jsonText(value);
    if (serialized == null) opaque = true;
    else texts.push(serialized);
  }
  return { prompt: texts.join("\n"), opaque };
}

function responseFromConverseOutput(output) {
  const { texts } = textsFromConverseContent(output?.output?.message?.content);
  return texts.length ? texts.join("\n") : null;
}

function responseFromInvokeBody(body) {
  if (Array.isArray(body.content)) {               // messages-style chat responses
    const { texts } = textsFromConverseContent(body.content);
    if (texts.length) return texts.join("\n");
  }
  if (body.output && typeof body.output === "object") {  // nova
    const { texts } = textsFromConverseContent(body.output?.message?.content);
    if (texts.length) return texts.join("\n");
  }
  if (Array.isArray(body.results) && body.results.length) {  // titan
    const text = body.results[0]?.outputText;
    if (typeof text === "string" && text.trim()) return text;
  }
  for (const key of ["generation", "outputs", "text", "completion"]) {  // llama / mistral / cohere
    const value = body[key];
    if (typeof value === "string" && value.trim()) return value;
    if (Array.isArray(value) && value.length && value[0] && typeof value[0] === "object") {
      const text = value[0].text;
      if (typeof text === "string" && text.trim()) return text;
    }
  }
  return null;
}

function bodyToString(body) {
  if (body == null) return null;
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  return null;
}

function parseJsonObject(raw) {
  if (typeof raw !== "string" || !raw.trim()) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------
// the scan call (same hardened client as the other AWS integrations)
// --------------------------------------------------------------------------

async function scan(endpoint, apiKey, payload, timeoutMs) {
  if (!/^https:\/\//i.test(endpoint)) {
    return { verdict: null, error: `refusing non-HTTPS endpoint: ${endpoint}` };
  }
  const url = endpoint.replace(/\/+$/, "") + SCAN_PATH;
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-pan-token": apiKey },
      body: JSON.stringify(payload),
      // A redirect would re-send x-pan-token to whatever host the 3xx names; refuse.
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (err?.name === "TimeoutError" || err?.name === "AbortError") {
      return { verdict: null, error: `scan timed out after ${timeoutMs} ms` };
    }
    const reason = err?.cause?.code || err?.cause?.message || err?.message || String(err);
    return { verdict: null, error: `network error reaching AIRS: ${reason}` };
  }
  let raw = null;
  let readError = null;
  try {
    raw = await readCapped(response, MAX_SCAN_BODY_BYTES);
    if (raw == null) readError = `scan response exceeds ${MAX_SCAN_BODY_BYTES} bytes`;
  } catch (err) {
    readError = err?.name === "TimeoutError" || err?.name === "AbortError"
      ? `scan timed out after ${timeoutMs} ms`
      : `error reading scan response: ${err?.message ?? String(err)}`;
  }
  if (!response.ok) {
    return { verdict: null, error: `HTTP ${response.status} from AIRS: ${(raw ?? "").slice(0, 500)}` };
  }
  if (readError != null) return { verdict: null, error: readError };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { verdict: null, error: "scan response is not JSON" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { verdict: null, error: `unexpected scan response shape: ${Array.isArray(parsed) ? "array" : typeof parsed}` };
  }
  return { verdict: parsed, error: null };
}

/**
 * The response body as text, or null when it runs past `limit` bytes. The
 * deadline is enforced by the AbortSignal above; this is the other half of
 * the same guarantee -- a verdict is a small JSON document, and buffering an
 * unbounded body from a broken or hostile peer would be the failure mode
 * rather than the scan. Over the cap the read is cancelled and the caller
 * follows the onError posture.
 */
async function readCapped(response, limit) {
  const reader = response.body?.getReader?.();
  if (!reader) return response.text();   // no stream to meter (empty body)
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    body.set(chunk, at);
    at += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

// --------------------------------------------------------------------------
// the hook
// --------------------------------------------------------------------------

const VALID_OPTIONS = new Set([
  "appName", "profileName", "profileId", "sessionId", "appUser",
  "onBlock", "onVerdict", "onError", "onUnscannable",
  "strictVerdict", "applyMaskedData", "scanPrompt", "scanResponse", "timeoutMs",
]);

function normalizeConfig(options) {
  const unknown = Object.keys(options).filter((key) => !VALID_OPTIONS.has(key));
  if (unknown.length) throw new TypeError(`unknown options: ${unknown.sort().join(", ")}`);
  const cfg = {
    appName: options.appName ?? null,
    profileName: options.profileName ?? null,
    profileId: options.profileId ?? null,
    sessionId: options.sessionId ?? null,
    appUser: options.appUser ?? null,
    onBlock: options.onBlock ?? "raise",
    onVerdict: options.onVerdict ?? null,
    onError: options.onError ?? "block",
    onUnscannable: options.onUnscannable ?? "block",
    strictVerdict: options.strictVerdict ?? false,
    applyMaskedData: options.applyMaskedData ?? false,
    scanPrompt: options.scanPrompt ?? true,
    scanResponse: options.scanResponse ?? true,
    timeoutMs: options.timeoutMs ?? 10_000,
  };
  if (!["raise", "respond"].includes(cfg.onBlock)) {
    throw new RangeError('onBlock must be "raise" or "respond"');
  }
  if (!["block", "allow"].includes(cfg.onError)) {
    throw new RangeError('onError must be "block" or "allow"');
  }
  if (!["block", "allow"].includes(cfg.onUnscannable)) {
    throw new RangeError('onUnscannable must be "block" or "allow"');
  }
  return cfg;
}

const PROTECTED_CLIENTS = new WeakSet();

/**
 * Register AIRS scanning on one BedrockRuntimeClient. Returns the client.
 * Protecting the same client twice is a no-op, not a double scan.
 *
 * The middleware is added on the client's middleware stack, so every command
 * later sent through this client is covered -- the four model-invocation
 * operations are scanned, everything else passes through untouched.
 */
export function protectClient(client, options = {}) {
  if (PROTECTED_CLIENTS.has(client)) return client;
  const cfg = normalizeConfig(options);
  client.middlewareStack.add(makeScanMiddleware(cfg), {
    step: "initialize",
    priority: "high",
    name: "prismaAirsScanMiddleware",
    tags: ["PRISMA_AIRS"],
    override: true,
  });
  // With cacheMiddleware enabled, Client.send caches the fully-resolved
  // handler per command constructor; a handler resolved BEFORE protection
  // would keep bypassing the scan. Drop any cache so the next send
  // re-resolves through the middleware just added.
  if ("handlers" in client) client.handlers = undefined;
  PROTECTED_CLIENTS.add(client);
  return client;
}

function makeScanMiddleware(cfg) {
  return (next, context) => async (args) => {
    const operation = String(context?.commandName || "").replace(/Command$/, "");
    if (!HOOK_OPERATIONS.has(operation)) return next(args);

    const transactionId = randomUUID();
    const modelId = typeof args?.input?.modelId === "string" ? args.input.modelId : null;
    let promptText = null;

    // -- leg 1: before the request is serialized, signed, or sent ----------
    if (cfg.scanPrompt) {
      const { prompt, opaque } = extractPrompt(operation, args?.input);
      if (opaque && cfg.onUnscannable === "block") {
        // Documents, images, video, audio, or a block shape this hook does
        // not recognize ride in this request; their content cannot be
        // inspected as text, so the fail-closed posture governs.
        log(cfg, "prompt", "unscannable", transactionId, 0,
          { operation, note: "opaque or unrecognized content" });
        return blockPrompt(cfg, { action: "block", category: "unscannable" },
          transactionId, operation);
      }
      if (typeof prompt !== "string" || !prompt.trim()) {
        log(cfg, "prompt", "unscannable", transactionId, 0, { operation });
        if (cfg.onUnscannable === "block") {
          return blockPrompt(cfg, { action: "block", category: "unscannable" },
            transactionId, operation);
        }
      } else {
        const { blockedVerdict } = await runLeg(cfg, "prompt", { prompt },
          transactionId, operation, modelId);
        if (blockedVerdict) {
          return blockPrompt(cfg, blockedVerdict, transactionId, operation);
        }
        promptText = prompt;
      }
    }

    // AWS errors (HTTP >= 300, SDK exceptions) reject here and propagate
    // untouched: an error response carries no model output, and scanning or
    // blocking it would only mask the real exception.
    const result = await next(args);

    // -- leg 2: after the response is deserialized, before the caller ------
    if (!cfg.scanResponse) return result;
    if ((result?.response?.statusCode ?? 200) >= 300) return result;
    if (STREAM_OPERATIONS.has(operation)) {
      // The body is an event stream still on the wire; there is nothing
      // complete to scan here. See the README's streaming section.
      log(cfg, "response", "skipped-stream", transactionId, 0, { operation });
      return result;
    }

    const output = result.output;
    const responseText = extractResponse(operation, output);
    if (typeof responseText !== "string" || !responseText.trim()) {
      log(cfg, "response", "unscannable", transactionId, 0, { operation });
      if (cfg.onUnscannable === "block") {
        blockResponse(cfg, output, { action: "block", category: "unscannable" },
          transactionId, operation);
      }
      return result;
    }

    const contents = { response: responseText };
    if (promptText) contents.prompt = promptText;
    const { blockedVerdict, allowVerdict } = await runLeg(cfg, "response", contents,
      transactionId, operation, modelId);
    if (blockedVerdict) {
      blockResponse(cfg, output, blockedVerdict, transactionId, operation);
      return result;
    }
    if (cfg.applyMaskedData) {
      const masked = allowVerdict?.response_masked_data?.data;
      if (masked) {
        const replaced = applyMaskedText(output, masked, operation);
        log(cfg, "response", replaced ? "masked" : "mask-unappliable",
          transactionId, 0, { operation });
        if (!replaced) {
          blockResponse(cfg, output, { action: "block", category: "mask_unappliable" },
            transactionId, operation);
        }
      }
    }
    return result;
  };
}

/**
 * {prompt, opaque} for the operation's input. A body the extractor cannot
 * walk at all is reported opaque rather than raised: an extraction failure
 * must route through the onUnscannable posture, never out of the caller's
 * send().
 */
function extractPrompt(operation, input) {
  try {
    if (operation.startsWith("Converse")) {
      return promptFromConverseBody(input);
    }
    const raw = bodyToString(input?.body);
    if (raw == null) return { prompt: null, opaque: false };
    const body = parseJsonObject(raw);
    if (body) {
      const { prompt, opaque } = promptFromInvokeBody(body);
      if (prompt == null && !opaque) return { prompt: raw, opaque: false };
      return { prompt, opaque };
    }
    return { prompt: raw, opaque: false };
  } catch {
    return { prompt: null, opaque: true };
  }
}

/** The response text to scan, or null -- which the caller reads as unscannable. */
function extractResponse(operation, output) {
  try {
    if (operation === "Converse") {
      return responseFromConverseOutput(output);
    }
    // InvokeModel: output.body is a Uint8Array (Uint8ArrayBlobAdapter); reading
    // it is non-destructive, so nothing needs restoring on the allow path.
    const raw = bodyToString(output?.body);
    if (raw == null) return null;
    const body = parseJsonObject(raw);
    if (body) return responseFromInvokeBody(body) ?? raw;
    return raw;
  } catch {
    return null;
  }
}

// -- shared plumbing --------------------------------------------------------

async function runLeg(cfg, leg, contents, transactionId, operation, modelId) {
  const apiKey = process.env.PRISMA_AIRS_API_KEY;
  const profileName = cfg.profileName || process.env.PRISMA_AIRS_PROFILE_NAME;
  const endpoint = process.env.PRISMA_AIRS_URL || DEFAULT_ENDPOINT;
  const aiProfile = {};
  if (cfg.profileId) aiProfile.profile_id = cfg.profileId;
  if (profileName) aiProfile.profile_name = profileName;
  if (!apiKey || !Object.keys(aiProfile).length) {
    const reason = "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set";
    log(cfg, leg, "error", transactionId, 0, { error: reason, operation });
    return cfg.onError === "block"
      ? { blockedVerdict: { action: "block", category: "airs_error", error: reason }, allowVerdict: null }
      : { blockedVerdict: null, allowVerdict: null };
  }
  const metadata = { app_name: cfg.appName ? `${APP_NAME_PREFIX}-${cfg.appName}` : APP_NAME_PREFIX };
  if (cfg.appUser) metadata.app_user = cfg.appUser;
  if (modelId) metadata.ai_model = modelId;
  const payload = {
    transaction_id: transactionId,
    ai_profile: aiProfile,
    metadata,
    contents: [contents],
  };
  if (cfg.sessionId) payload.session_id = String(cfg.sessionId);

  const started = performance.now();
  const { verdict, error: scanError } = await scan(endpoint, apiKey, payload, cfg.timeoutMs);
  const elapsed = performance.now() - started;

  let error = scanError;
  let action = null;
  if (error == null && !("action" in verdict)) {
    error = "scan response carries no action verdict";
  }
  if (error == null) {
    action = String(verdict.action).toLowerCase();
    if (!["allow", "block"].includes(action)) {
      error = `unknown scan action ${JSON.stringify(verdict.action)}`;
    }
  }
  if (error == null && cfg.strictVerdict && action === "allow" && (
    verdict.timeout || verdict.error ||
    ["error", "timeout"].includes(String(verdict.category ?? "").toLowerCase())
  )) {
    error = `degraded scan under strictVerdict (timeout=${verdict.timeout} error=${verdict.error})`;
  }
  if (error != null) {
    log(cfg, leg, "error", transactionId, elapsed, { error, operation });
    return cfg.onError === "block"
      ? { blockedVerdict: { action: "block", category: "airs_error", error }, allowVerdict: null }
      : { blockedVerdict: null, allowVerdict: null };
  }
  log(cfg, leg, action, transactionId, elapsed, { verdict, operation });
  if (cfg.onVerdict) {
    try {
      cfg.onVerdict(leg, verdict);
    } catch (err) {
      logger.warn(`prisma_airs ${JSON.stringify({ warning: "onVerdict callback failed", error: String(err?.message ?? err) })}`);
    }
  }
  return action === "block"
    ? { blockedVerdict: verdict, allowVerdict: null }
    : { blockedVerdict: null, allowVerdict: verdict };
}

/** Prompt-leg block: throw, or short-circuit with a shaped response (next is never called). */
function blockPrompt(cfg, verdict, transactionId, operation) {
  if (cfg.onBlock === "raise") {
    throw new PrismaAirsBlocked("prompt", verdict, transactionId, operation);
  }
  const message = `This request was blocked by Prisma AIRS (prompt scan, ` +
    `category=${verdict?.category}, scan_id=${verdict?.scan_id}).`;
  const prismaAirs = {
    blocked: true,
    leg: "prompt",
    category: verdict?.category,
    scan_id: verdict?.scan_id,
    transaction_id: transactionId,
  };
  let output;
  if (operation === "ConverseStream") {
    // A minimal, valid event stream (the SDK types `stream` as an
    // AsyncIterable of ConverseStreamOutput events): the standard consumer
    // loop plays it back exactly like a real streamed reply.
    output = {
      $metadata: { httpStatusCode: 200 },
      $prismaAirs: prismaAirs,
      stream: (async function* () {
        yield { messageStart: { role: "assistant" } };
        yield { contentBlockDelta: { delta: { text: message }, contentBlockIndex: 0 } };
        yield { contentBlockStop: { contentBlockIndex: 0 } };
        yield { messageStop: { stopReason: "content_filtered" } };
      })(),
    };
  } else if (operation === "InvokeModelWithResponseStream") {
    // The SDK types `body` as an AsyncIterable of ResponseStream events
    // ({chunk: {bytes}}); one chunk carries the whole block notice.
    const chunk = new TextEncoder().encode(JSON.stringify({ prisma_airs_blocked: true, message }));
    output = {
      $metadata: { httpStatusCode: 200 },
      $prismaAirs: prismaAirs,
      contentType: "application/json",
      body: (async function* () {
        yield { chunk: { bytes: chunk } };
      })(),
    };
  } else if (operation === "InvokeModel") {
    output = {
      $metadata: { httpStatusCode: 200 },
      $prismaAirs: prismaAirs,
      contentType: "application/json",
      body: blobBody(JSON.stringify({ prisma_airs_blocked: true, message })),
    };
  } else {
    output = {
      $metadata: { httpStatusCode: 200 },
      $prismaAirs: prismaAirs,
      output: { message: { role: "assistant", content: [{ text: message }] } },
      stopReason: "content_filtered",
      usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    };
  }
  return { response: { statusCode: 200, headers: {}, body: "" }, output };
}

/** Response-leg block: throw, or rewrite the deserialized output in place. */
function blockResponse(cfg, output, verdict, transactionId, operation) {
  if (cfg.onBlock === "raise") {
    throw new PrismaAirsBlocked("response", verdict, transactionId, operation);
  }
  const message = `The model response was withheld by Prisma AIRS ` +
    `(category=${verdict?.category}, scan_id=${verdict?.scan_id}).`;
  const replaced = replaceResponseText(output, message, operation);
  // The withheld reply carries no tool call any more, so the stopReason that
  // announced one must not survive: an agent loop branching on "tool_use"
  // would hunt for a block that is gone.
  if (replaced && operation === "Converse") output.stopReason = "content_filtered";
  output.$prismaAirs = {
    blocked: true,
    leg: "response",
    category: verdict?.category,
    scan_id: verdict?.scan_id,
    transaction_id: transactionId,
  };
}

/** Withhold the whole reply: the model text is replaced by the block notice. */
function replaceResponseText(output, text, operation) {
  if (operation === "Converse") {
    const message = output?.output?.message;
    if (message && Array.isArray(message.content)) {
      message.content = [{ text }];
      return true;
    }
    return false;
  }
  if (output && "body" in output) {
    const bytes = blobBody(JSON.stringify({ prisma_airs: "response replaced", text }));
    // Keep the SDK's Uint8ArrayBlobAdapter prototype (transformToString etc.)
    // on the replacement bytes.
    const original = output.body;
    if (original instanceof Uint8Array &&
        Object.getPrototypeOf(original) !== Uint8Array.prototype) {
      Object.setPrototypeOf(bytes, Object.getPrototypeOf(original));
    }
    output.body = bytes;
    output.contentType = "application/json";
    return true;
  }
  return false;
}

/**
 * Masking is not a block: the verdict allowed the turn, so the masked text is
 * substituted INTO the existing text blocks and every other block -- a
 * toolUse above all -- is left standing. Collapsing the content list would
 * delete the tool call from a benign turn and strand the agent loop.
 * Returns false when no text block can carry the substitution, which the
 * caller turns into the mask_unappliable withhold path. stopReason is never
 * rewritten here: nothing was filtered.
 */
function applyMaskedText(output, text, operation) {
  if (operation !== "Converse") return replaceResponseText(output, text, operation);
  const content = output?.output?.message?.content;
  if (!Array.isArray(content)) return false;
  const textBlocks = content.filter((block) => block && typeof block.text === "string");
  if (!textBlocks.length) return false;
  // AIRS returns the masked form of the whole scanned response, so the first
  // text block carries it and the rest would only repeat what it already says.
  textBlocks[0].text = text;
  for (const block of textBlocks.slice(1)) block.text = "";
  return true;
}

/**
 * Bytes shaped like the SDK's Uint8ArrayBlobAdapter, which is how
 * InvokeModelCommandOutput types `body`. A prompt-leg block short-circuits
 * the chain before the deserializer runs, so there is no original body whose
 * prototype could be borrowed; attaching the reader methods keeps
 * `body.transformToString()` working for callers that read the documented
 * way, on the one path where they least expect a surprise.
 */
function blobBody(text) {
  const bytes = new TextEncoder().encode(text);
  return Object.defineProperties(bytes, {
    transformToString: {
      value: function transformToString(encoding = "utf-8") {
        return encoding === "base64"
          ? Buffer.from(this).toString("base64")
          : new TextDecoder(encoding).decode(this);
      },
    },
    transformToByteArray: {
      value: function transformToByteArray() { return new Uint8Array(this); },
    },
  });
}

function log(cfg, leg, action, transactionId, elapsedMs, { verdict, error, operation, note } = {}) {
  const record = {
    leg,
    action,
    transaction_id: transactionId,
    ms: Math.round(elapsedMs * 10) / 10,
  };
  if (note) record.note = note;
  if (operation) record.operation = operation;
  if (verdict && typeof verdict === "object") {
    record.category = verdict.category;
    record.scan_id = verdict.scan_id;
    record.report_id = verdict.report_id;
    const detected = {};
    for (const side of ["prompt_detected", "response_detected"]) {
      const hits = Object.entries(verdict[side] ?? {})
        .filter(([, value]) => value)
        .map(([key]) => key);
      if (hits.length) detected[side] = hits;
    }
    if (Object.keys(detected).length) record.detected = detected;
    if (verdict.timeout) record.timeout = true;
    if (verdict.error) record.error_flag = true;
  }
  if (error != null) record.error = error;
  const line = `prisma_airs ${JSON.stringify(record)}`;
  if (["allow", "skipped-stream", "masked"].includes(action)) logger.info(line);
  else logger.warn(line);
}
