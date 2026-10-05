"""
Prisma AIRS decorator for AWS Lambda handlers.

Wraps a Lambda handler so that:

  1. the inbound prompt is scanned by Prisma AIRS *before* the handler body runs
     (a blocked prompt never reaches the handler -- or any model behind it), and
  2. the handler's response is scanned *before* Lambda returns it to the caller
     (a blocked response is withheld).

Single file, standard library only. Copy it into your deployment package next
to your handler -- no layer, no requirements.txt, works on any python3.x
Lambda runtime and with any model provider the handler calls.

The decorator populates the full scan-request surface the platform can know:
transaction_id (the Lambda request id), session_id, metadata.app_name / app_user /
ai_model / user_ip (auto-extracted from API Gateway events) / agent_meta, the
AI profile by name or id, and per-content code_prompt / code_response /
grounding context. On the verdict side it enforces `action`, surfaces
detection-service `timeout` / `error` / `errors`, can treat degraded scans as
failures (strict_verdict), and can substitute DLP-masked output
(apply_masked_data). `tool_event` is deliberately absent: nothing at the
function boundary can see tool calls -- that field belongs to the agent-loop
integrations.

Environment variables (standard Prisma AIRS names):

    PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
    PRISMA_AIRS_PROFILE_NAME   required   security profile name (or pass profile_name= / profile_id=)
    PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region

Usage:

    from prisma_airs_decorator import airs_protect

    @airs_protect(app_name="support-chat")
    def handler(event, context):
        ...
"""

import base64
import functools
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid

logger = logging.getLogger("prisma_airs")
if logger.level == logging.NOTSET:
    # Lambda's default (text) log config leaves the root level at WARNING;
    # without this, every INFO allow-line would be dropped before CloudWatch.
    logger.setLevel(logging.INFO)

DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_PATH = "/v1/scan/sync/request"

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-Lambda-support-chat").
APP_NAME_PREFIX = "AWS-Lambda"

# Keys the default extractors look for, in order, when the event / result is a
# JSON object. If your handler reads a different field, pass prompt_from= /
# response_from= so the scan sees exactly what the handler sees.
PROMPT_KEYS = ("prompt", "message", "input", "query", "question", "text")
RESPONSE_KEYS = ("response", "completion", "output", "answer", "reply", "message", "text")


class PrismaAirsBlocked(Exception):
    """Raised when a scan blocks an invocation that is not an HTTP proxy event.

    Raising -- rather than returning a block marker -- is what keeps the
    default safe on asynchronous event sources (SQS, SNS, EventBridge, S3,
    async invoke): Lambda engages retry, DLQ, and failure-destination
    semantics only when the invocation errors. A returned value would count
    as success and the event source would silently delete the messages.
    """

    def __init__(self, leg, verdict, transaction_id):
        self.leg = leg
        self.verdict = verdict
        self.transaction_id = transaction_id
        super().__init__(
            "blocked by Prisma AIRS on the %s leg (category=%s scan_id=%s transaction_id=%s)"
            % (leg, verdict.get("category"), verdict.get("scan_id"), transaction_id)
        )


class _Skip:
    """Sentinel: this leg is intentionally not scanned (not an extraction failure)."""


_SKIP = _Skip()

# Public alias: return SKIP from a custom prompt_from/response_from to say
# "this invocation intentionally carries nothing to scan" (e.g. health checks)
# without tripping the fail-closed on_unscannable posture.
SKIP = _SKIP


# --------------------------------------------------------------------------
# default extractors
# --------------------------------------------------------------------------

def _is_http_event(event):
    """True for API Gateway (REST/HTTP/WebSocket), Function URL and ALB events.

    Recognized on the proxy envelope itself and not only on "body": an HTTP API
    (payload format 2.0) or Function URL event omits "body" entirely on a
    bodyless request -- a GET route, an OPTIONS preflight, an empty POST -- and
    those still have to receive the 403 rather than a raise the gateway renders
    as a generic 5xx. The final clause keeps every other envelope that carries a
    request context and a body, whose route marker sits somewhere this list does
    not name (an API Gateway WebSocket event puts routeKey inside
    requestContext).
    """
    if not isinstance(event, dict):
        return False
    ctx = event.get("requestContext")
    if not isinstance(ctx, dict):
        ctx = {}
    return bool(
        "httpMethod" in event                    # REST (v1) and ALB
        or "routeKey" in event                   # HTTP API (v2)
        or "http" in ctx                         # HTTP API (v2) / Function URL
        or "elb" in ctx                          # ALB target group
        or (event.get("version") == "2.0" and ctx)
        or ("body" in event and "requestContext" in event)  # any other proxy envelope
    )


def _decoded_body(envelope, raw):
    """A proxy envelope's body as text, base64-decoded when the envelope says so.

    Returns None when a flagged body is not valid base64 or does not decode to
    text (gzip, images, any binary media type): a blob is not scannable, so the
    leg must fail closed on the on_unscannable posture rather than scan -- or
    write a mask into -- the wrapper.
    """
    if not (isinstance(envelope, dict) and envelope.get("isBase64Encoded")):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except Exception:
        return None


def _encoded_body(envelope, text):
    """Re-wrap a rewritten body exactly the way the envelope it came from was wrapped."""
    if isinstance(envelope, dict) and envelope.get("isBase64Encoded") and isinstance(text, str):
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    return text


def _http_body(event):
    raw = event.get("body")
    if raw is None:
        return None
    return _decoded_body(event, raw)


def _first_text(obj, keys):
    if isinstance(obj, str):
        return obj if obj.strip() else None
    if isinstance(obj, dict):
        for key in keys:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def default_prompt_from(event):
    """Prompt text from an API Gateway/ALB proxy event or a direct-invoke payload."""
    if _is_http_event(event):
        raw = _http_body(event)
        if raw is None:
            return None
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return raw if isinstance(raw, str) and raw.strip() else None
        return _first_text(parsed, PROMPT_KEYS)
    return _first_text(event, PROMPT_KEYS)


def default_response_from(result):
    """Response text from an API Gateway-shaped result or a plain return value."""
    if isinstance(result, dict) and "statusCode" in result:
        status = result.get("statusCode")
        if isinstance(status, int) and status >= 400:
            return _SKIP  # the handler's own error path carries no model output
        raw = result.get("body")
        if raw is None:
            return None
        raw = _decoded_body(result, raw)
        if raw is None:
            return None  # binary body: unscannable -- never scan the base64 wrapper
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return raw if isinstance(raw, str) and raw.strip() else None
        return _first_text(parsed, RESPONSE_KEYS)
    return _first_text(result, RESPONSE_KEYS)


def default_user_ip_from(event, context=None):
    """End-user IP from API Gateway v1/v2 request context, else X-Forwarded-For."""
    if not isinstance(event, dict):
        return None
    ctx = event.get("requestContext") or {}
    ip = (ctx.get("http") or {}).get("sourceIp") or (ctx.get("identity") or {}).get("sourceIp")
    if ip:
        return ip
    headers = event.get("headers") or {}
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == "x-forwarded-for" and isinstance(value, str):
            return value.split(",")[0].strip() or None
    return None


# --------------------------------------------------------------------------
# the scan call
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send x-pan-token to whatever host the 3xx names; refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())

# A verdict is a few kilobytes; a body approaching this is a peer that will
# never finish. Same cap the other language integrations in this repo apply.
MAX_SCAN_RESPONSE_BYTES = 10 * 1024 * 1024
_READ_CHUNK = 65536


def _read_bounded(resp, deadline):
    """Read a scan response under a total deadline and a size cap.

    urlopen(timeout=) is a per-recv timeout: it restarts on every successful
    read, so a peer dribbling one byte at a time holds the handler far past
    `timeout` and the on_error posture is never reached. read1() returns what a
    single recv delivered, which is what lets the clock be checked in between.
    """
    read1 = getattr(resp, "read1", None)
    chunks = []
    total = 0
    while True:
        chunk = read1(_READ_CHUNK) if read1 is not None else resp.read(_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_SCAN_RESPONSE_BYTES:
            raise ValueError("scan response exceeded %d bytes" % MAX_SCAN_RESPONSE_BYTES)
        chunks.append(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError("scan exceeded its time budget while reading the response")


def _scan(endpoint, api_key, payload, timeout):
    """POST one scan request. Returns (verdict_dict, None) or (None, error_str)."""
    if not endpoint.lower().startswith("https://"):
        return None, "refusing non-HTTPS endpoint: %s" % endpoint
    url = endpoint.rstrip("/") + SCAN_PATH
    # One wall-clock budget for the whole call, not one per socket read.
    deadline = time.monotonic() + timeout
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "x-pan-token": api_key},
            method="POST",
        )
        with _OPENER.open(request, timeout=timeout) as resp:
            parsed = json.loads(_read_bounded(resp, deadline).decode("utf-8"))
        if not isinstance(parsed, dict):
            return None, "unexpected scan response shape: %s" % type(parsed).__name__
        return parsed, None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = _read_bounded(exc, deadline).decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return None, "HTTP %s from AIRS: %s" % (exc.code, body)
    except urllib.error.URLError as exc:
        return None, "network error reaching AIRS: %s" % exc.reason
    except Exception as exc:  # timeout, bad JSON, ...
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# the decorator
# --------------------------------------------------------------------------

def airs_protect(
    app_name=None,
    profile_name=None,
    profile_id=None,
    prompt_from=None,
    response_from=None,
    session_id_from=None,
    app_user_from=None,
    ai_model=None,
    user_ip_from=None,
    agent_meta=None,
    context_from=None,
    code_prompt_from=None,
    code_response_from=None,
    on_block=None,
    on_verdict=None,
    on_error="block",
    on_unscannable="block",
    strict_verdict=False,
    apply_masked_data=False,
    response_write=None,
    scan_prompt=True,
    scan_response=True,
    timeout=10.0,
):
    """
    Scan a Lambda handler's inbound prompt and outbound response with Prisma AIRS.

    Identity & profile
      app_name          appended to "AWS-Lambda-" in metadata.app_name so SCM
                        logs identify both the integration and your application.
      profile_name      overrides PRISMA_AIRS_PROFILE_NAME.
      profile_id        AI profile UUID; either name or id must resolve.

    Extractors (all optional callables; return None when absent, SKIP to say
    "intentionally nothing to scan here")
      prompt_from(event)                -> str    text to scan before the handler
      response_from(result)             -> str    text to scan after the handler
      session_id_from(event, context)   -> str    conversation/session id (SCM correlation)
      app_user_from(event, context)     -> str    metadata.app_user (end user identity)
      user_ip_from(event, context)      -> str    metadata.user_ip; defaults to the
                                                  API Gateway source IP / X-Forwarded-For
      context_from(event)               -> str    grounding context for the response leg
                                                  (feeds the "ungrounded" detection)
      code_prompt_from(event)           -> str    pre-extracted code from the prompt
      code_response_from(result)        -> str    pre-extracted code from the response

    Static metadata
      ai_model          string (or callable(event, context)) for metadata.ai_model.
      agent_meta        dict with agent_id / agent_version / agent_arn. Off by
                        default: a plain Lambda is not an AI agent; the agent
                        integrations populate this themselves.

    Verdict handling
      on_block          callable(leg, verdict, event, context) -> replacement
                        return value. Default: HTTP 403 for proxy events,
                        raises PrismaAirsBlocked for everything else so async
                        event sources keep retry/DLQ semantics.
      on_verdict        callable(leg, verdict) observer, called for every scan
                        verdict (allow or block) -- metrics, audit, alerting.
      on_error          "block" (default) or "allow" when AIRS is unreachable,
                        times out, errors, or credentials are missing.
      on_unscannable    "block" (default) or "allow" when no text can be
                        extracted. Fail-closed so a misconfigured extractor is
                        caught on the first test, not discovered as a bypass.
      strict_verdict    when True, a verdict whose detection services report
                        timeout/error (the `timeout` and `error` flags, an
                        error/timeout category, or a populated per-service
                        `errors` array) is treated per on_error even if action
                        says "allow" -- a degraded scan is not proof of clean
                        content.
      apply_masked_data when True and the profile returns response_masked_data,
                        the masked text REPLACES the handler's response (DLP
                        masking instead of blocking). The substitution is
                        verified by re-reading the rewritten result with the
                        response extractor; if the masked text cannot be put
                        where that extractor reads, the response is withheld.
      response_write    callable(result, masked_text) -> new result, for
                        writing masked text into custom result shapes. Required
                        alongside a custom response_from: the default writer
                        will not guess which field a custom reader used.

    Toggles
      scan_prompt / scan_response       skip a leg entirely.
      timeout                           seconds per scan call (two per invocation).
    """
    if on_error not in ("block", "allow"):
        raise ValueError('on_error must be "block" or "allow"')
    if on_unscannable not in ("block", "allow"):
        raise ValueError('on_unscannable must be "block" or "allow"')

    extract_prompt = prompt_from or default_prompt_from
    extract_response = response_from or default_response_from
    extract_user_ip = user_ip_from or default_user_ip_from
    full_app_name = "%s-%s" % (APP_NAME_PREFIX, app_name) if app_name else APP_NAME_PREFIX

    def _maybe(fn, *args):
        if fn is None:
            return None
        try:
            value = fn(*args)
        except Exception as exc:
            logger.warning("prisma_airs %s", json.dumps(
                {"warning": "metadata extractor %s failed" % getattr(fn, "__name__", "?"),
                 "error": str(exc)}))
            return None
        return value if isinstance(value, str) and value.strip() else None

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(event, context=None):
            api_key = os.environ.get("PRISMA_AIRS_API_KEY")
            profile = profile_name or os.environ.get("PRISMA_AIRS_PROFILE_NAME")
            endpoint = os.environ.get("PRISMA_AIRS_URL", DEFAULT_ENDPOINT)

            # transaction_id: the platform's own unique id for this invocation, so a
            # scan in SCM matches a request in CloudWatch one-to-one.
            transaction_id = getattr(context, "aws_request_id", None) or str(uuid.uuid4())
            session_id = _maybe(session_id_from, event, context)

            metadata = {"app_name": full_app_name}
            app_user = _maybe(app_user_from, event, context)
            if app_user:
                metadata["app_user"] = app_user
            model = _maybe(ai_model, event, context) if callable(ai_model) else ai_model
            if isinstance(model, str) and model.strip():
                metadata["ai_model"] = model
            user_ip = _maybe(extract_user_ip, event, context)
            if user_ip:
                metadata["user_ip"] = user_ip
            if isinstance(agent_meta, dict) and agent_meta:
                metadata["agent_meta"] = agent_meta

            ai_profile = {}
            if profile_id:
                ai_profile["profile_id"] = profile_id
            if profile:
                ai_profile["profile_name"] = profile

            def blocked(leg, verdict):
                if on_block is not None:
                    return on_block(leg, verdict, event, context)
                return _default_block_response(event, leg, verdict, transaction_id)

            leg_verdicts = {}

            def run_leg(leg, contents):
                """Returns None to continue, or a verdict dict that must block."""
                if not api_key or not ai_profile:
                    reason = "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set"
                    _log_leg(leg, "error", transaction_id, 0.0, error=reason)
                    return {"action": "block", "category": "airs_error", "error": reason} if on_error == "block" else None
                payload = {
                    # transaction_id supersedes the legacy tr_id field name;
                    # the service still honors tr_id but it is being retired.
                    "transaction_id": transaction_id,
                    "ai_profile": ai_profile,
                    "metadata": metadata,
                    "contents": [contents],
                }
                if session_id:
                    payload["session_id"] = session_id
                started = time.monotonic()
                verdict, error = _scan(endpoint, api_key, payload, timeout)
                elapsed = (time.monotonic() - started) * 1000.0
                if error is None and "action" not in verdict:
                    error = "scan response carries no action verdict"
                if error is None:
                    action = str(verdict["action"]).lower()
                    if action not in ("allow", "block"):
                        error = "unknown scan action %r" % action
                if error is None and strict_verdict and action == "allow" and (
                    verdict.get("timeout") or verdict.get("error") or verdict.get("errors")
                    or str(verdict.get("category", "")).lower() in ("error", "timeout")
                ):
                    error = "degraded scan under strict_verdict (timeout=%s error=%s services=%s)" % (
                        verdict.get("timeout"), verdict.get("error"),
                        ",".join(_degraded_services(verdict)) or "-")
                if error is not None:
                    _log_leg(leg, "error", transaction_id, elapsed, verdict=verdict, error=error)
                    return {"action": "block", "category": "airs_error", "error": error} if on_error == "block" else None
                # Only an explicit "allow" passes. A confused endpoint that
                # answers 200 without a real verdict must not fail open.
                leg_verdicts[leg] = verdict
                _log_leg(leg, action, transaction_id, elapsed, verdict=verdict, session_id=session_id)
                if on_verdict is not None:
                    try:
                        on_verdict(leg, verdict)
                    except Exception as exc:
                        logger.warning("prisma_airs %s", json.dumps(
                            {"warning": "on_verdict callback failed", "error": str(exc)}))
                return verdict if action == "block" else None

            # ---- leg 1: the prompt, before the handler runs -------------
            prompt_text = None
            if scan_prompt:
                extracted = None
                try:
                    extracted = extract_prompt(event)
                except Exception as exc:
                    _log_leg("prompt", "extract-error", transaction_id, 0.0, error=str(exc))
                if isinstance(extracted, _Skip):
                    _log_leg("prompt", "skipped", transaction_id, 0.0)
                elif not isinstance(extracted, str) or not extracted.strip():
                    _log_leg("prompt", "unscannable", transaction_id, 0.0,
                             neutral=(on_unscannable == "allow"))
                    if on_unscannable == "block":
                        return blocked("prompt", {"action": "block", "category": "unscannable"})
                else:
                    prompt_text = extracted
                    contents = {"prompt": prompt_text}
                    code_prompt = _maybe(code_prompt_from, event)
                    if code_prompt:
                        contents["code_prompt"] = code_prompt
                    verdict = run_leg("prompt", contents)
                    if verdict is not None:
                        return blocked("prompt", verdict)

            # ---- the handler itself -------------------------------------
            result = fn(event, context)

            # ---- leg 2: the response, before it leaves ------------------
            if scan_response:
                response_text = None
                try:
                    response_text = extract_response(result)
                except Exception as exc:
                    _log_leg("response", "extract-error", transaction_id, 0.0, error=str(exc))
                if isinstance(response_text, _Skip):
                    _log_leg("response", "skipped", transaction_id, 0.0)
                elif not isinstance(response_text, str) or not response_text.strip():
                    _log_leg("response", "unscannable", transaction_id, 0.0,
                             neutral=(on_unscannable == "allow"))
                    if on_unscannable == "block":
                        return blocked("response", {"action": "block", "category": "unscannable"})
                else:
                    # Send the prompt alongside the response: AIRS detections
                    # that need conversational context see both sides.
                    contents = {"response": response_text}
                    if prompt_text:
                        contents["prompt"] = prompt_text
                    grounding = _maybe(context_from, event)
                    if grounding:
                        contents["context"] = grounding
                    code_response = _maybe(code_response_from, result)
                    if code_response:
                        contents["code_response"] = code_response
                    verdict = run_leg("response", contents)
                    if verdict is not None:
                        return blocked("response", verdict)
                    if apply_masked_data:
                        verdict = leg_verdicts.get("response") or {}
                        md = verdict.get("response_masked_data")
                        masked = md.get("data") if isinstance(md, dict) else None
                        if masked:
                            result = _apply_masking(result, masked, transaction_id,
                                                    response_write, blocked)

            return result

        return wrapper

    def _apply_masking(result, masked, transaction_id, response_write, blocked):
        # Reached only on an allow whose profile handed back masked output:
        # the masked text must replace the original -- otherwise withhold.
        writer = None
        if isinstance(masked, str) and masked.strip():
            if response_write is not None:
                writer = response_write
            elif response_from is None:
                writer = _default_response_write
            # With a custom response_from the default writer would have to guess
            # which field the reader chose, and a wrong guess leaves the unmasked
            # original exactly where the application reads it: withhold instead.
        rewritten = None
        if writer is not None:
            try:
                rewritten = writer(result, masked)
            except Exception:
                rewritten = None
        if rewritten is not None:
            # Verify the substitution through the reader: a writer that rewrote
            # some other field would otherwise leave the sensitive original in
            # place and still log a "masked" audit line.
            try:
                reread = extract_response(rewritten)
            except Exception:
                reread = None
            if not isinstance(reread, str) or reread.strip() != masked.strip():
                rewritten = None
        if rewritten is None:
            _log_leg("response", "mask-unappliable", transaction_id, 0.0)
            return blocked("response", {"action": "block", "category": "mask_unappliable"})
        _log_leg("response", "masked", transaction_id, 0.0)
        return rewritten

    return decorator


# --------------------------------------------------------------------------
# block response, masking writer, logging
# --------------------------------------------------------------------------

def _default_block_response(event, leg, verdict, transaction_id):
    if _is_http_event(event):
        return {
            "statusCode": 403,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "blocked": True,
                "leg": leg,
                "category": verdict.get("category", "unknown"),
                "scan_id": verdict.get("scan_id"),
                "transaction_id": transaction_id,
                "message": "Request blocked by Prisma AIRS (%s scan)." % leg,
            }),
        }
    # Non-HTTP events (direct invoke, SQS, SNS, EventBridge, ...): raise, so
    # async event sources get retry/DLQ semantics instead of a silent success.
    # Pass on_block= to return a value instead if your sync caller prefers one.
    raise PrismaAirsBlocked(leg, verdict, transaction_id)


def _default_response_write(result, masked_text):
    """Write masked text back into the shapes default_response_from understands."""
    if isinstance(result, str):
        return masked_text
    if isinstance(result, dict) and "statusCode" in result:
        raw = result.get("body")
        if raw is None:
            return None
        raw = _decoded_body(result, raw)
        if raw is None:
            return None  # a body we cannot decode is a body we cannot round-trip
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                parsed = None
        else:
            parsed = raw
        if isinstance(parsed, dict):
            for key in RESPONSE_KEYS:
                if isinstance(parsed.get(key), str) and parsed[key].strip():
                    body = dict(parsed)
                    body[key] = masked_text
                    out = dict(result)
                    # Re-wrap as it arrived: plaintext under isBase64Encoded=true
                    # is an envelope the gateway cannot decode.
                    out["body"] = (_encoded_body(result, json.dumps(body))
                                   if isinstance(raw, str) else body)
                    return out
            return None
        if isinstance(raw, str) and raw.strip():
            out = dict(result)
            out["body"] = _encoded_body(result, masked_text)
            return out
        return None
    if isinstance(result, dict):
        for key in RESPONSE_KEYS:
            if isinstance(result.get(key), str) and result[key].strip():
                out = dict(result)
                out[key] = masked_text
                return out
    return None


def _degraded_services(verdict):
    """"feature:status" for each entry of a verdict's per-service `errors` array."""
    errors = verdict.get("errors")
    if not isinstance(errors, list):
        return []
    return ["%s:%s" % (e.get("feature"), e.get("status"))
            for e in errors if isinstance(e, dict)][:5]


# Outcomes that are routine on healthy traffic: a scan ran (or was skipped on
# purpose) and nothing was withheld. Everything else logs at WARNING.
_NEUTRAL_ACTIONS = ("allow", "skipped", "masked")


def _log_leg(leg, action, transaction_id, elapsed_ms, verdict=None, error=None, session_id=None,
             neutral=False):
    record = {"leg": leg, "action": action, "transaction_id": transaction_id, "ms": round(elapsed_ms, 1)}
    if session_id:
        record["session_id"] = session_id
    if isinstance(verdict, dict):
        record["category"] = verdict.get("category")
        record["scan_id"] = verdict.get("scan_id")
        record["report_id"] = verdict.get("report_id")
        detected = {}
        for side in ("prompt_detected", "response_detected"):
            # A verdict field of an unexpected type is loggable but unreadable:
            # logging must never break a scan decision the caller already made.
            side_hits = verdict.get(side)
            hits = [k for k, v in side_hits.items() if v] if isinstance(side_hits, dict) else []
            if hits:
                detected[side] = hits
        if detected:
            record["detected"] = detected
        details = {}
        for side in ("prompt_detection_details", "response_detection_details"):
            d = verdict.get(side)
            if not isinstance(d, dict):
                continue
            tgd = d.get("topic_guardrails_details")
            tg = tgd.get("blocked_topics") if isinstance(tgd, dict) else None
            toxd = d.get("toxic_content_details")
            tox = toxd.get("toxic_categories") if isinstance(toxd, dict) else None
            if tg:
                details.setdefault(side, {})["blocked_topics"] = tg
            if tox:
                details.setdefault(side, {})["toxic_categories"] = tox
        if details:
            record["details"] = details
        if verdict.get("timeout"):
            record["timeout"] = True
        if verdict.get("error"):
            record["error_flag"] = True
        svc_errors = _degraded_services(verdict)
        if svc_errors:
            record["svc_errors"] = svc_errors
        for flag, field in (("masked", "response_masked_data"),
                            ("prompt_masked", "prompt_masked_data")):
            md = verdict.get(field) or {}
            if isinstance(md, dict) and md.get("data"):
                record[flag] = True
    if error is not None:
        record["error"] = error
    line = "prisma_airs %s" % json.dumps(record)
    if neutral or action in _NEUTRAL_ACTIONS:
        logger.info(line)
    else:
        logger.warning(line)
