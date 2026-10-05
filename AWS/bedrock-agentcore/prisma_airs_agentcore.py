"""
Prisma AIRS guard for Amazon Bedrock AgentCore agents.

Unlike the SDK-client hooks, an AgentCore agent is *your* loop: the runtime hosts
the code you wrote, and there is no universal seam to intercept an arbitrary agent
loop. So this integration is a guard you call at the four legs of that loop:

    before-model   scan the prompt going to the model
    after-model    scan the model's response
    before-tool    scan a tool call's input   (as a first-class tool_event)
    after-tool     scan a tool call's output  (where injected tool results and
                   leaked credentials are actually caught)

This is the first seat that sees tool calls as tool calls. It is the deepest of
the AWS integrations and the narrowest in fit: you place the calls, and only the
loop you instrument is covered.

The guard pulls the AgentCore request id and session id from the runtime context
when it is available (so a scan in Strata Cloud Manager lines up with an
invocation in the AgentCore logs), and falls back to a generated id off-runtime.

Single file, standard library only. AgentCore runs Python, so no other SDK is
required to scan; boto3/Bedrock are only needed by your agent, not by the guard.

Environment variables (standard Prisma AIRS names):

    PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
    PRISMA_AIRS_PROFILE_NAME   required   security profile name (or pass profile_name=)
    PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region

Usage (hand-rolled loop):

    from prisma_airs_agentcore import PrismaAirsGuard

    guard = PrismaAirsGuard(app_name="support-agent", agent_arn=MY_AGENT_ARN)

    guard.scan_prompt(user_text)                 # raises PrismaAirsBlocked on block
    reply = model_call(user_text)
    guard.scan_response(reply, prompt=user_text)

    guard.scan_tool_input(name, args)            # before running a tool
    result = run_tool(name, args)
    guard.scan_tool_output(name, args, result)   # before feeding it back to the model

Usage (wrap a tool so both legs are automatic):

    @guard.guard_tool(server_name="crm")
    def read_ticket(ticket_id: str) -> str:
        ...

The wrapper matches the tool it decorates: an async tool is awaited and a
generator tool is drained before the output leg scans, so that leg always sees
what the tool produced rather than a coroutine or generator object.
"""

import asyncio
import functools
import inspect
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid

logger = logging.getLogger("prisma_airs")
if logger.level == logging.NOTSET:
    logger.setLevel(logging.INFO)

DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_PATH = "/v1/scan/sync/request"

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-AgentCore-support-agent").
APP_NAME_PREFIX = "AWS-AgentCore"

# The scan API accepts exactly one tool ecosystem today: "mcp". Every other
# value (agentcore, python, custom, ...) is rejected with HTTP 400
# "unsupported ecosystem" -- measured against the live service, 2026-08-18.
TOOL_ECOSYSTEM = "mcp"


class PrismaAirsBlocked(Exception):
    """Raised by a guard leg when a scan verdict blocks."""

    def __init__(self, leg, verdict, transaction_id, detail=None):
        self.leg = leg
        self.verdict = verdict
        self.transaction_id = transaction_id
        self.detail = detail or {}
        super().__init__(
            "blocked by Prisma AIRS on the %s leg (category=%s scan_id=%s transaction_id=%s)"
            % (leg, verdict.get("category"), verdict.get("scan_id"), transaction_id)
        )


# --------------------------------------------------------------------------
# runtime context (optional -- present only inside AgentCore)
# --------------------------------------------------------------------------

def _runtime_ids():
    """(request_id, session_id) from the AgentCore runtime context, or (None, None)."""
    try:
        from bedrock_agentcore.runtime import BedrockAgentCoreContext
    except Exception:
        return None, None
    try:
        return BedrockAgentCoreContext.get_request_id(), BedrockAgentCoreContext.get_session_id()
    except Exception:
        return None, None


def _runtime_agent_arn():
    """The runtime's own agent ARN, recovered the way the SDK does -- from
    cloud.resource_id in OTEL_RESOURCE_ATTRIBUTES. Returns None off-runtime.
    (The runtime injects this; there is no BEDROCK_AGENTCORE_AGENT_ARN env var.)"""
    attrs = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    for pair in attrs.split(","):
        key, _, value = pair.partition("=")
        if key.strip() == "cloud.resource_id" and value.strip():
            arn = value.strip()
            # OTEL sets this to either a runtime ARN or a runtime-endpoint ARN;
            # the SDK normalizes the endpoint form to the plain runtime ARN, and
            # so must we, or an exact-match join on the ARN the AgentCore console
            # shows will miss every scan this guard reports.
            if "/runtime-endpoint/" in arn:
                arn = arn.split("/runtime-endpoint/")[0]
            return arn
    return None


# --------------------------------------------------------------------------
# the scan call (identical hardening to the other AWS integrations)
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send x-pan-token to whatever host the 3xx names; refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())

# urlopen(timeout=) is a per-recv timeout that resets on every successful read,
# so a peer that trickles bytes can hold the caller far past `timeout`. The body
# is read against one wall-clock deadline, and capped at 10 MB so a runaway
# response cannot be buffered into the agent's memory.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_READ_CHUNK = 65536


def _read_bounded(resp, deadline):
    """Read a response body under a total deadline and a size cap.

    read1() hands back whatever one recv delivered, where read() keeps looping
    on the socket until the chunk is full. Taking one recv at a time and
    checking the clock between them is what bounds the whole read to the
    configured timeout plus at most one recv.
    """
    read_once = getattr(resp, "read1", None) or resp.read
    chunks = []
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("AIRS response exceeded the scan deadline")
        chunk = read_once(_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise ValueError("AIRS response exceeded %d bytes" % _MAX_RESPONSE_BYTES)
        chunks.append(chunk)


def _scan(endpoint, api_key, payload, timeout):
    if not endpoint.lower().startswith("https://"):
        return None, "refusing non-HTTPS endpoint: %s" % endpoint
    url = endpoint.rstrip("/") + SCAN_PATH
    # One wall-clock budget for the whole call, not one per socket read. Hoisted
    # out of the try so the error path can read its diagnostic body under it too.
    deadline = time.monotonic() + timeout
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "x-pan-token": api_key},
            method="POST")
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
    except Exception as exc:
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# the guard
# --------------------------------------------------------------------------

class PrismaAirsGuard:
    """Scans the four legs of an AgentCore agent loop with Prisma AIRS.

    app_name        appended to "AWS-AgentCore-" in metadata.app_name.
    profile_name    overrides PRISMA_AIRS_PROFILE_NAME.
    profile_id      AI profile UUID; name or id must resolve.
    agent_arn       stamped into metadata.agent_meta.agent_arn.
    agent_id / agent_version  optional agent_meta fields.
    app_user        end-user identity for metadata.app_user.
    ai_model        model id for metadata.ai_model.
    on_error        "block" (default) or "allow" when AIRS is unreachable / errors.
    on_unscannable  "block" (default) or "allow" when there is no text to scan.
    strict_verdict  treat a detection-service timeout/error verdict as on_error.
    on_verdict      callable(leg, verdict) observer for every scan.
    timeout         seconds per scan call.

    Each scan_* method returns the verdict dict on allow and raises
    PrismaAirsBlocked on block (unless on_error/on_unscannable relax it).
    """

    def __init__(self, app_name=None, profile_name=None, profile_id=None,
                 agent_arn=None, agent_id=None, agent_version=None,
                 app_user=None, ai_model=None, on_error="block",
                 on_unscannable="block", strict_verdict=False,
                 on_verdict=None, timeout=10.0):
        if on_error not in ("block", "allow"):
            raise ValueError('on_error must be "block" or "allow"')
        if on_unscannable not in ("block", "allow"):
            raise ValueError('on_unscannable must be "block" or "allow"')
        self.app_name = app_name
        self.profile_name = profile_name
        self.profile_id = profile_id
        self.agent_meta = {}
        resolved_arn = agent_arn or _runtime_agent_arn()
        if resolved_arn:
            self.agent_meta["agent_arn"] = resolved_arn
        if agent_id:
            self.agent_meta["agent_id"] = agent_id
        if agent_version:
            self.agent_meta["agent_version"] = agent_version
        self.app_user = app_user
        self.ai_model = ai_model
        self.on_error = on_error
        self.on_unscannable = on_unscannable
        self.strict_verdict = strict_verdict
        self.on_verdict = on_verdict
        self.timeout = timeout

    # -- public legs ------------------------------------------------------

    def scan_prompt(self, prompt, session_id=None, transaction_id=None):
        return self._text_leg("prompt", {"prompt": _as_text(prompt)},
                              session_id, transaction_id)

    def scan_response(self, response, prompt=None, context=None,
                      session_id=None, transaction_id=None):
        contents = {"response": _as_text(response)}
        if prompt:
            contents["prompt"] = _as_text(prompt)
        if context:
            contents["context"] = _as_text(context)
        return self._text_leg("response", contents, session_id, transaction_id)

    def scan_tool_input(self, tool_name, tool_input, server_name="agent-tools",
                        session_id=None, transaction_id=None):
        return self._tool_leg("tool_input", tool_name, tool_input, None,
                             server_name, session_id, transaction_id)

    def scan_tool_output(self, tool_name, tool_input, tool_output,
                         server_name="agent-tools", session_id=None, transaction_id=None):
        return self._tool_leg("tool_output", tool_name, tool_input, tool_output,
                             server_name, session_id, transaction_id)

    def guard_tool(self, server_name="agent-tools"):
        """Decorator: scan a tool function's input before it runs and its output
        before it returns, so both tool legs are automatic. The wrapper matches
        the tool it decorates -- an async tool is awaited and a generator tool is
        drained before the output leg scans, so that leg never scans a coroutine
        or generator object and reports it as inspected."""
        def decorator(fn):
            try:
                sig = inspect.signature(fn)
            except (ValueError, TypeError):
                sig = None
            tool_name = getattr(fn, "__name__", "tool")

            def bind_input(args, kwargs):
                # Bind to parameter NAMES so the scanned input reads as data
                # ({"ticket_id": "T-1"}), not as Python call structure
                # ({"args": [...], "kwargs": {...}}) -- the latter trips a
                # source-code detector on every guarded call.
                if sig is None:
                    return {"args": list(args), "kwargs": dict(kwargs)}
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    tool_input = dict(bound.arguments)
                except TypeError:
                    return {"args": list(args), "kwargs": dict(kwargs)}
                # Drop a receiver (self/cls) so a bound object's repr --
                # possibly carrying connection strings or secrets --
                # never reaches the scan payload or the logs.
                first = next(iter(sig.parameters), None)
                if first in ("self", "cls"):
                    tool_input.pop(first, None)
                return tool_input

            # A scan is a blocking urllib call, so the async wrappers offload it
            # to a worker thread instead of parking the runtime's event loop
            # (asyncio.to_thread carries the context, so the AgentCore request
            # and session ids still resolve inside the scan).
            if inspect.isasyncgenfunction(fn):
                @functools.wraps(fn)
                async def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    await asyncio.to_thread(self.scan_tool_input, tool_name, tool_input,
                                            server_name=server_name)
                    items = [item async for item in fn(*args, **kwargs)]
                    await asyncio.to_thread(self.scan_tool_output, tool_name, tool_input,
                                            items, server_name=server_name)
                    for item in items:
                        yield item
            elif inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    await asyncio.to_thread(self.scan_tool_input, tool_name, tool_input,
                                            server_name=server_name)
                    result = await fn(*args, **kwargs)
                    if _is_lazy(result):
                        return self._unscannable_tool_output(tool_name, result)
                    await asyncio.to_thread(self.scan_tool_output, tool_name, tool_input,
                                            result, server_name=server_name)
                    return result
            elif inspect.isgeneratorfunction(fn):
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    self.scan_tool_input(tool_name, tool_input, server_name=server_name)
                    items = list(fn(*args, **kwargs))
                    self.scan_tool_output(tool_name, tool_input, items, server_name=server_name)
                    for item in items:
                        yield item
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    self.scan_tool_input(tool_name, tool_input, server_name=server_name)
                    result = fn(*args, **kwargs)
                    if _is_lazy(result):
                        return self._unscannable_tool_output(tool_name, result)
                    self.scan_tool_output(tool_name, tool_input, result, server_name=server_name)
                    return result
            return wrapper
        return decorator

    # -- internals --------------------------------------------------------

    def _ids(self, session_id, transaction_id):
        rt_request, rt_session = _runtime_ids()
        return (transaction_id or rt_request or str(uuid.uuid4()),
                session_id or rt_session)

    def _metadata(self):
        metadata = {"app_name": "%s-%s" % (APP_NAME_PREFIX, self.app_name)
                    if self.app_name else APP_NAME_PREFIX}
        if self.app_user:
            metadata["app_user"] = self.app_user
        if self.ai_model:
            metadata["ai_model"] = self.ai_model
        if self.agent_meta:
            metadata["agent_meta"] = dict(self.agent_meta)
        return metadata

    def _text_leg(self, leg, contents, session_id, transaction_id):
        transaction_id, session_id = self._ids(session_id, transaction_id)
        # Each leg is judged on ITS OWN field: a prompt carried as context must
        # not satisfy the response leg's check, or a model turn with no text
        # would be recorded as a response that was scanned and allowed.
        text = contents.get("response") if leg == "response" else contents.get("prompt")
        if not isinstance(text, str) or not text.strip():
            self._log(leg, "unscannable", transaction_id, 0.0)
            if self.on_unscannable == "block":
                verdict = {"action": "block", "category": "unscannable"}
                raise PrismaAirsBlocked(leg, verdict, transaction_id)
            return None
        return self._run(leg, [contents], session_id, transaction_id)

    def _tool_leg(self, leg, tool_name, tool_input, tool_output,
                  server_name, session_id, transaction_id):
        transaction_id, session_id = self._ids(session_id, transaction_id)
        tool_event = {
            "metadata": {
                "ecosystem": TOOL_ECOSYSTEM,   # only "mcp" is accepted by the service
                "method": "tools/call",
                "server_name": server_name,
                "tool_invoked": tool_name,
            },
            "input": _as_json(tool_input),
        }
        if tool_output is not None:
            tool_event["output"] = _as_json(tool_output)
        return self._run(leg, [{"tool_event": tool_event}], session_id, transaction_id,
                        tool_name=tool_name)

    def _unscannable_tool_output(self, tool_name, result):
        """A tool that handed back a coroutine or a lazy iterator produced
        nothing to scan yet -- it was a callable `inspect` could not classify at
        decoration time. That is unscannable output, not clean output, so it
        follows the on_unscannable posture instead of being scanned as a repr."""
        transaction_id, _ = self._ids(None, None)
        self._log("tool_output", "unscannable", transaction_id, 0.0, tool_name=tool_name)
        if self.on_unscannable == "block":
            # The value is being discarded here, so close what can be closed
            # rather than leave a bare "was never awaited" warning behind it.
            if inspect.iscoroutine(result) or inspect.isgenerator(result):
                result.close()
            raise PrismaAirsBlocked("tool_output",
                                    {"action": "block", "category": "unscannable"},
                                    transaction_id, detail={"tool_name": tool_name})
        return result

    def _run(self, leg, contents, session_id, transaction_id, tool_name=None):
        api_key = os.environ.get("PRISMA_AIRS_API_KEY")
        profile = self.profile_name or os.environ.get("PRISMA_AIRS_PROFILE_NAME")
        endpoint = os.environ.get("PRISMA_AIRS_URL", DEFAULT_ENDPOINT)
        ai_profile = {}
        if self.profile_id:
            ai_profile["profile_id"] = self.profile_id
        if profile:
            ai_profile["profile_name"] = profile
        if not api_key or not ai_profile:
            reason = "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set"
            self._log(leg, "error", transaction_id, 0.0, error=reason, tool_name=tool_name)
            if self.on_error == "block":
                raise PrismaAirsBlocked(leg, {"action": "block", "category": "airs_error",
                                              "error": reason}, transaction_id)
            return None
        payload = {"transaction_id": transaction_id, "ai_profile": ai_profile,
                   "metadata": self._metadata(), "contents": contents}
        if session_id:
            payload["session_id"] = str(session_id)
        started = time.monotonic()
        verdict, error = _scan(endpoint, api_key, payload, self.timeout)
        elapsed = (time.monotonic() - started) * 1000.0
        if error is None and "action" not in verdict:
            error = "scan response carries no action verdict"
        if error is None:
            action = str(verdict["action"]).lower()
            if action not in ("allow", "block"):
                error = "unknown scan action %r" % action
        if error is None and self.strict_verdict and action == "allow" and (
            verdict.get("timeout") or verdict.get("error")
            or str(verdict.get("category", "")).lower() in ("error", "timeout")
        ):
            error = "degraded scan under strict_verdict"
        if error is not None:
            self._log(leg, "error", transaction_id, elapsed, error=error, tool_name=tool_name)
            if self.on_error == "block":
                raise PrismaAirsBlocked(leg, {"action": "block", "category": "airs_error",
                                              "error": error}, transaction_id)
            return None
        self._log(leg, action, transaction_id, elapsed, verdict=verdict, tool_name=tool_name)
        if self.on_verdict is not None:
            try:
                self.on_verdict(leg, verdict)
            except Exception as exc:
                logger.warning("prisma_airs %s", json.dumps(
                    {"warning": "on_verdict callback failed", "error": str(exc)}))
        if action == "block":
            raise PrismaAirsBlocked(leg, verdict, transaction_id,
                                    detail={"tool_name": tool_name} if tool_name else None)
        return verdict

    def _log(self, leg, action, transaction_id, elapsed_ms, verdict=None, error=None,
             tool_name=None):
        record = {"leg": leg, "action": action, "transaction_id": transaction_id,
                  "ms": round(elapsed_ms, 1)}
        if tool_name:
            record["tool"] = tool_name
        if isinstance(verdict, dict):
            record["category"] = verdict.get("category")
            record["scan_id"] = verdict.get("scan_id")
            record["report_id"] = verdict.get("report_id")
            # A degraded-but-HTTP-200 verdict can carry the wrong type in any
            # of these fields, and summarising one for a log line must never
            # break a scan decision: every read is type-guarded, and the block
            # is wrapped, so a malformed verdict cannot raise past the caller's
            # except PrismaAirsBlocked.
            try:
                detected = {}
                for side in ("prompt_detected", "response_detected"):
                    side_map = verdict.get(side)
                    if not isinstance(side_map, dict):
                        continue
                    hits = [k for k, v in side_map.items() if v]
                    if hits:
                        detected[side] = hits
                td = verdict.get("tool_detected")
                if isinstance(td, dict):
                    summary = td.get("summary")
                    threats = summary.get("threats") if isinstance(summary, dict) else None
                    if threats:
                        detected["tool_threats"] = threats
                    if td.get("verdict"):
                        record["tool_verdict"] = td.get("verdict")
                if detected:
                    record["detected"] = detected
            except Exception as exc:
                record["summary_error"] = str(exc)
            if verdict.get("timeout"):
                record["timeout"] = True
            if verdict.get("error"):
                record["error_flag"] = True
        if error is not None:
            record["error"] = error
        line = "prisma_airs %s" % json.dumps(record, default=str)
        # Neutral outcomes read as INFO: an allow, and unscannable content when
        # the posture lets it through. A block or an error is a WARNING.
        neutral = action == "allow" or (action == "unscannable"
                                        and self.on_unscannable == "allow")
        (logger.info if neutral else logger.warning)(line)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _is_lazy(value):
    """True for a value that has produced nothing to scan yet -- a coroutine, an
    async generator or a generator. Scanning its repr would log an allow for
    output nobody inspected."""
    return (inspect.isawaitable(value) or inspect.isasyncgen(value)
            or inspect.isgenerator(value))


def _as_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, default=str)


def _as_json(value):
    """tool_event input/output are raw JSON strings on the wire."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)
