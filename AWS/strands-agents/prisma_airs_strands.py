"""
Prisma AIRS hooks for the Strands Agents SDK.

Strands has a first-class typed hook system: you implement HookProvider, register
callbacks against event classes, and pass the provider to the agent. This module
is one such provider that scans the four legs of a Strands agent with Palo Alto
Networks Prisma AI Runtime Security (AIRS):

    BeforeModelCallEvent   scan the prompt   -> block by setting `cancel`
    AfterModelCallEvent    scan the response -> block by setting `retry` (see below)
    BeforeToolCallEvent    scan tool input   -> block by setting `cancel_tool`
    AfterToolCallEvent     scan tool output  -> block by REPLACING `result`

A fifth callback on BeforeInvocationEvent scans nothing: it resets the
response-leg retry budget so one invocation cannot spend the next one's.

The whole user-facing surface is one class and one constructor argument:

    from strands import Agent
    from prisma_airs_strands import PrismaAIRSHooks

    agent = Agent(tools=[...], hooks=[PrismaAIRSHooks(app_name="support-agent")])

Enforcement is shaped by what each Strands event permits writing -- this is a
capability boundary in the framework, not a choice:

  * Prompt and pre-tool blocks are clean cancels; the model call / tool call
    does not happen.
  * A tool RESULT can be replaced outright, so a poisoned or leaking tool output
    is swapped for a safe error result before it re-enters the model.
  * A model RESPONSE, however, can only be RETRIED, never substituted
    (`AfterModelCallEvent` permits writing only `retry`). A blocked response is
    therefore discarded and the model is called again, up to `retry_limit`;
    after that the invocation fails closed. On a non-streaming agent the
    discarded message is not added to the conversation history. Note that
    Strands streams tokens to the agent's callback handler as the model
    produces them, so a consumer of that stream (including the default
    PrintingCallbackHandler) may have already seen the tokens before the
    verdict -- see the Limitations section of the README.

The callbacks are coroutines. Strands dispatches these five events only through
`invoke_callbacks_async`, so a plain `def` callback would run the blocking scan
inline on the caller's event loop and stall every other session sharing it under
`stream_async` / `invoke_async`; the scan client itself stays synchronous and is
handed to that loop's default executor instead. `Agent.structured_output()` and
`Agent.structured_output_async()` fire neither model-call event and are therefore
not covered -- see the Limitations section of the README.

Single file: the scan client is standard library; the Strands hook types are
imported at module load, so the SDK must be installed to import this module.

Environment variables (standard Prisma AIRS names):

    PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
    PRISMA_AIRS_PROFILE_NAME   required   security profile name (or pass profile_name=)
    PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region
"""

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
import weakref

from strands.hooks import HookProvider, HookRegistry
from strands.hooks.events import (
    AfterModelCallEvent,
    AfterToolCallEvent,
    BeforeInvocationEvent,
    BeforeModelCallEvent,
    BeforeToolCallEvent,
)

logger = logging.getLogger("prisma_airs")
if logger.level == logging.NOTSET:
    logger.setLevel(logging.INFO)

DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_PATH = "/v1/scan/sync/request"

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-Strands-support-agent").
APP_NAME_PREFIX = "AWS-Strands"

# The scan API accepts exactly one tool ecosystem today: "mcp". Every other
# value is rejected HTTP 400 "unsupported ecosystem" (measured live 2026-08-18).
TOOL_ECOSYSTEM = "mcp"

# Bounds on reading a scan response: chunk size, and the largest body accepted
# before the read is abandoned (matching the other AWS integrations).
READ_CHUNK_BYTES = 64 * 1024
MAX_BODY_BYTES = 10 * 1024 * 1024


class PrismaAirsResponseBlocked(Exception):
    """Raised when a model response stays blocked after retry_limit retries.

    A Strands AfterModelCallEvent can only retry a response, not substitute it,
    so once retries are exhausted the only fail-closed option is to error out.
    """

    def __init__(self, verdict, transaction_id, retries):
        self.verdict = verdict
        self.transaction_id = transaction_id
        self.retries = retries
        super().__init__(
            "model response blocked by Prisma AIRS after %d retries "
            "(category=%s scan_id=%s)"
            % (retries, verdict.get("category"), verdict.get("scan_id"))
        )


# --------------------------------------------------------------------------
# the scan call (identical hardening to the other AWS integrations)
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _read_bounded(resp, deadline):
    """Read a response body under a TOTAL deadline and a size cap.

    `timeout=` bounds one socket read, not the call: a peer that trickles bytes
    resets it on every read and can hold the caller far past the configured
    timeout, so the on_error posture is never reached. Read in chunks, stop the
    moment the deadline has passed, and refuse an oversized body.

    The chunk read is `read1()`, which returns after ONE underlying socket read.
    Plain `read(n)` blocks until it has all n bytes or hits EOF, and a verdict
    body is far smaller than one chunk -- so it is a single blocking call, the
    deadline below is evaluated once before it, and nothing is bounded."""
    read1 = getattr(resp, "read1", None) or resp.read
    chunks, total = [], 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("scan deadline exceeded while reading the response body")
        chunk = read1(READ_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise ValueError("scan response body exceeded %d bytes" % MAX_BODY_BYTES)
        chunks.append(chunk)


def _scan(endpoint, api_key, payload, timeout):
    if not endpoint.lower().startswith("https://"):
        return None, "refusing non-HTTPS endpoint: %s" % endpoint
    url = endpoint.rstrip("/") + SCAN_PATH
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "x-pan-token": api_key},
            method="POST")
        deadline = time.monotonic() + timeout
        with _OPENER.open(request, timeout=timeout) as resp:
            parsed = json.loads(_read_bounded(resp, deadline).decode("utf-8"))
        if not isinstance(parsed, dict):
            return None, "unexpected scan response shape: %s" % type(parsed).__name__
        return parsed, None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            # Diagnostic only, and the deadline is already spent by now: one
            # socket read via read1(), never a blocking wait for 4 KB.
            read1 = getattr(exc, "read1", None) or exc.read
            body = read1(4096).decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return None, "HTTP %s from AIRS: %s" % (exc.code, body)
    except urllib.error.URLError as exc:
        return None, "network error reaching AIRS: %s" % exc.reason
    except Exception as exc:
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# text extraction from Strands message / content shapes
# --------------------------------------------------------------------------

def _text_from_content(content):
    """Join the text of a Strands content-block list (Bedrock Converse shape)."""
    text, _, _ = _classify_content(content)
    return text


def _text_members(blocks):
    """(texts, missed) of a nested list of `{"text": ...}` members -- the shape
    citationsContent uses for both the generated answer and the cited source.
    `missed` is True when the list held anything else, which this walker cannot
    read as text."""
    if not isinstance(blocks, (list, tuple)):
        return [], True
    parts, missed = [], False
    for item in blocks:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
        else:
            missed = True
    return parts, missed


def _classify_content(content):
    """(text, has_tool, opaque) for a Strands content-block list (Converse shape).

    The block keys are an ALLOWLIST: the text-bearing shapes are extracted, and
    everything else -- document, image, video, or a block type added to the
    framework after this file was written -- sets `opaque`, which the fail-closed
    `on_unscannable` posture then governs, exactly as in the SDK-hook siblings. A
    content type this seat has never heard of must fail closed, not vanish while
    the leg reports a clean allow. `cachePoint` is the one benign exception: it
    is a caching marker carrying no content of its own, so it is neither text nor
    opaque and a prompt-caching agent is not blocked by it.

    A tool-use assistant turn and a tool-result user turn carry no plain text but
    are covered by the dedicated tool legs, so they set `has_tool` and the model
    legs skip them rather than treating them as unscannable.

    Nothing here may raise: a malformed message must reach the caller as
    `opaque` -- a scan decision -- never as an exception out of the agent's call."""
    if isinstance(content, str):
        return content, False, False
    if content is None:
        return "", False, False
    if not isinstance(content, (list, tuple)):
        return "", False, True
    parts, has_tool, opaque = [], False, False
    for block in content:
        if not isinstance(block, dict):
            opaque = True
        elif isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif "toolUse" in block or "toolResult" in block:
            has_tool = True
        elif "reasoningContent" in block:
            rc = block.get("reasoningContent")
            rc = rc if isinstance(rc, dict) else {}
            rt = rc.get("reasoningText")
            text = rt.get("text") if isinstance(rt, dict) else None
            if isinstance(text, str):
                parts.append(text)
            if not isinstance(text, str) or any(k != "reasoningText" for k in rc):
                # redactedContent is reasoning the provider encrypted, and any
                # other member here is not readable as text either
                opaque = True
        elif "guardContent" in block:
            gc = block.get("guardContent")
            gc = gc if isinstance(gc, dict) else {}
            gt = gc.get("text")
            text = gt.get("text") if isinstance(gt, dict) else None
            if isinstance(text, str):
                parts.append(text)
            if not isinstance(text, str) or any(k != "text" for k in gc):
                opaque = True
        elif "citationsContent" in block:
            # The model's own generated answer, plus the source text it cites.
            cc = block.get("citationsContent")
            cc = cc if isinstance(cc, dict) else {}
            found, missed = _text_members(cc.get("content"))
            parts.extend(found)
            citations = cc.get("citations")
            for citation in citations if isinstance(citations, (list, tuple)) else []:
                sourced, sub_missed = _text_members(
                    citation.get("sourceContent") if isinstance(citation, dict) else None)
                parts.extend(sourced)
                missed = missed or sub_missed
            opaque = opaque or missed
        elif "cachePoint" in block:
            pass  # a caching marker, carrying no content of its own
        else:
            # document, image, video, or a block type added to the framework
            # after this file was written -- not readable as text, so it fails
            # closed rather than riding to the model unscanned.
            opaque = True
    return "\n".join(parts), has_tool, opaque


def _message_key(message):
    """The durable id Strands stamps on every message it puts in history, or
    None for a message that has not been through the agent's append path -- such
    a message has no stable identity, so it is treated as never scanned."""
    tracking = message.get("tracking_id")
    return tracking if isinstance(tracking, str) and tracking else None


def _user_messages(messages):
    """The user-role messages of an agent's history, oldest first."""
    return [m for m in messages or []
            if isinstance(m, dict) and m.get("role") == "user"]


def _unscanned_user_content(users, scanned):
    """(text, has_tool, opaque, keys) of the user turns this leg must scan.

    The newest user message is always scanned. Any OLDER user message this
    provider has not scanned yet is scanned alongside it: one invocation can
    append several user turns at once (Strands accepts a Messages batch), and an
    agent can be built on a caller-supplied history -- in both shapes an earlier
    user turn would otherwise reach the model without ever having been the
    newest one. `has_tool` reads the newest turn only, since it exists to tell a
    tool-result continuation apart from an empty turn. `keys` are the message
    identities to record once the content has been adjudicated -- allowed or
    blocked -- so that no turn is ever sent to AIRS twice."""
    parts, has_tool, opaque, keys = [], False, False, []
    for index, message in enumerate(users):
        newest = index == len(users) - 1
        key = _message_key(message)
        if not newest and key is not None and key in scanned:
            continue
        text, tool, block_opaque = _classify_content(message.get("content"))
        if text:
            parts.append(text)
        if newest:
            has_tool = tool
        opaque = opaque or block_opaque
        if key is not None:
            keys.append(key)
    return "\n".join(parts), has_tool, opaque, keys


def _system_text(agent):
    system = getattr(agent, "system_prompt", None)
    if isinstance(system, str) and system.strip():
        return system
    content = getattr(agent, "system_prompt_content", None)
    text = _text_from_content(content)
    return text if text.strip() else None


# --------------------------------------------------------------------------
# the hook provider
# --------------------------------------------------------------------------

class PrismaAIRSHooks(HookProvider):
    """A Strands HookProvider that scans the four agent legs with Prisma AIRS.

    app_name       appended to "AWS-Strands-" in metadata.app_name.
    profile_name   overrides PRISMA_AIRS_PROFILE_NAME.
    profile_id     AI profile UUID; name or id must resolve.
    session_id     conversation id for SCM session correlation.
    app_user       end-user identity for metadata.app_user.
    ai_model       model id for metadata.ai_model.
    agent_arn/id/version   optional metadata.agent_meta fields.
    on_error       "block" (default) or "allow" when AIRS is unreachable / errors.
    on_unscannable "block" (default) or "allow" when a leg has no text to scan.
    strict_verdict treat a detection-service timeout/error verdict as on_error.
    on_verdict     callable(leg, verdict) observer for every scan.
    retry_limit    max response-leg retries before failing closed (default 2).
    tool_server    server_name label for tool_event metadata (default "strands-tools").
    timeout        seconds per scan call.
    """

    def __init__(self, app_name=None, profile_name=None, profile_id=None,
                 session_id=None, app_user=None, ai_model=None,
                 agent_arn=None, agent_id=None, agent_version=None,
                 on_error="block", on_unscannable="block", strict_verdict=False,
                 on_verdict=None, retry_limit=2, tool_server="strands-tools",
                 timeout=10.0):
        if on_error not in ("block", "allow"):
            raise ValueError('on_error must be "block" or "allow"')
        if on_unscannable not in ("block", "allow"):
            raise ValueError('on_unscannable must be "block" or "allow"')
        self.app_name = app_name
        self.profile_name = profile_name
        self.profile_id = profile_id
        self.session_id = session_id
        self.app_user = app_user
        self.ai_model = ai_model
        self.agent_meta = {}
        if agent_arn:
            self.agent_meta["agent_arn"] = agent_arn
        if agent_id:
            self.agent_meta["agent_id"] = agent_id
        if agent_version:
            self.agent_meta["agent_version"] = agent_version
        self.on_error = on_error
        self.on_unscannable = on_unscannable
        self.strict_verdict = strict_verdict
        self.on_verdict = on_verdict
        self.retry_limit = retry_limit
        self.tool_server = tool_server
        self.timeout = timeout
        # response-leg retry counters, keyed weakly by agent
        self._retries = weakref.WeakKeyDictionary()
        # ids of the user messages already scanned, keyed weakly by agent
        self._scanned = weakref.WeakKeyDictionary()
        # block reasons for user messages already adjudicated as blocked, keyed
        # weakly by agent
        self._blocked = weakref.WeakKeyDictionary()

    @staticmethod
    def _mark_cancelled(event):
        state = getattr(event, "invocation_state", None)
        if isinstance(state, dict):
            state["_prisma_cancelled"] = True

    @staticmethod
    def _record_blocked(scanned, blocked, keys, reason):
        """Remember a user turn adjudicated as blocked. It stays in
        `agent.messages` and would still reach the model, so the prompt leg
        keeps cancelling while it is there -- but its content is never sent to
        AIRS again."""
        scanned.update(keys)
        for key in keys:
            blocked[key] = reason

    # -- registration -----------------------------------------------------

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeInvocationEvent, self._on_before_invocation)
        registry.add_callback(BeforeModelCallEvent, self._on_before_model)
        registry.add_callback(AfterModelCallEvent, self._on_after_model)
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool)
        registry.add_callback(AfterToolCallEvent, self._on_after_tool)

    # -- legs -------------------------------------------------------------

    def _on_before_invocation(self, event: BeforeInvocationEvent) -> None:
        # The response-leg retry budget is per invocation, and a count left
        # behind by an invocation that ended some other way (a tool leg raising,
        # a turn limit) would be spent by the NEXT invocation on the same agent,
        # shrinking its budget. This is the one callback that runs at the start
        # of every invocation, so the budget is cleared here as well as on the
        # response leg's own exits. It scans nothing, so it stays a plain
        # callback rather than a coroutine.
        self._retries.pop(event.agent, None)

    async def _on_before_model(self, event: BeforeModelCallEvent) -> None:
        agent = event.agent
        scanned = self._scanned.setdefault(agent, set())
        blocked = self._blocked.setdefault(agent, {})
        try:
            users = _user_messages(getattr(agent, "messages", None))
            # This state tracks messages, so it is pruned to the messages still
            # in history: a ConversationManager that trims the conversation must
            # not leave ids behind, and removing a blocked turn -- the documented
            # way to clear one -- must let the agent run again.
            live, held = set(), None
            for message in users:
                key = _message_key(message)
                if key is None:
                    continue
                live.add(key)
                if held is None and key in blocked:
                    held = key
            scanned.intersection_update(live)
            for key in [k for k in blocked if k not in live]:
                del blocked[key]
            user, has_tool, opaque, keys = _unscanned_user_content(users, scanned)
        except (AttributeError, TypeError) as exc:
            # A history this file cannot read is a scan decision, never an
            # exception out of the caller's agent(...) call.
            self._log("prompt", "unscannable", self._tid(), 0.0,
                      error="conversation could not be read: %s" % exc)
            if self.on_unscannable == "block":
                event.cancel = self._reason(
                    "prompt", {"action": "block", "category": "unscannable"})
                self._mark_cancelled(event)
            return
        if held is not None:
            # A turn already adjudicated as blocked is still in history and would
            # still reach the model, so the leg cancels again -- without a scan.
            # Re-sending content AIRS has already blocked, on every later
            # invocation, would grow the payload for the life of the agent.
            self._log("prompt", "block", self._tid(), 0.0,
                      note="blocked user turn still in history")
            event.cancel = blocked[held]
            self._mark_cancelled(event)
            return
        parts = []
        system = _system_text(agent)
        if system:
            parts.append(system)
        if user:
            parts.append(user)
        text = "\n".join(parts)
        # Content in the user turn that cannot be inspected as text.
        if opaque and self.on_unscannable == "block":
            self._log("prompt", "unscannable", self._tid(), 0.0,
                      note="content not readable as text")
            reason = self._reason("prompt", {"action": "block", "category": "unscannable"})
            self._record_blocked(scanned, blocked, keys, reason)
            event.cancel = reason
            self._mark_cancelled(event)
            return
        if not text.strip():
            # A tool-result continuation turn has no fresh user text (the tool
            # legs already scanned that result), so skip. Block only a turn that
            # has neither text nor tool content and only when fail-closed.
            if not has_tool and self.on_unscannable == "block":
                self._log("prompt", "unscannable", self._tid(), 0.0)
                reason = self._reason("prompt", {"action": "block", "category": "unscannable"})
                self._record_blocked(scanned, blocked, keys, reason)
                event.cancel = reason
                self._mark_cancelled(event)
                return
            scanned.update(keys)
            return
        verdict = await self._run("prompt", [{"prompt": text}])
        if verdict is _UNSCANNABLE:  # on_error="allow" -- fail open, do not cancel
            scanned.update(keys)
            return
        if verdict is not None:  # block
            reason = self._reason("prompt", verdict)
            self._record_blocked(scanned, blocked, keys, reason)
            event.cancel = reason
            self._mark_cancelled(event)
            return
        # Recorded once the content is on its way to the model. A turn is scanned
        # exactly once per agent, whichever way it was adjudicated.
        scanned.update(keys)

    async def _on_after_model(self, event: AfterModelCallEvent) -> None:
        # Our own before-model cancel produces a synthetic assistant turn and
        # still fires AfterModelCallEvent (event loop shares invocation_state);
        # never re-scan our own block notice. Both early returns end the
        # invocation, so the retry budget is cleared with them.
        state = getattr(event, "invocation_state", None)
        if isinstance(state, dict) and state.pop("_prisma_cancelled", False):
            self._retries.pop(event.agent, None)
            return
        stop = getattr(event, "stop_response", None)
        if stop is None:  # a failed model call -- nothing to scan
            self._retries.pop(event.agent, None)
            return
        message = getattr(stop, "message", None)
        text, has_tool, opaque = _classify_content(
            message.get("content") if isinstance(message, dict) else None)
        if opaque and self.on_unscannable == "block":
            # Document/image/video in the model's own turn cannot be inspected
            # as text, and this event cannot substitute. Fail closed without
            # retrying -- the same shape would come back and loop.
            self._retries.pop(event.agent, None)
            raise PrismaAirsResponseBlocked(
                {"action": "block", "category": "unscannable"}, self._tid(), 0)
        if not text.strip():
            # A tool-use turn carries no text; the tool legs cover it. Skip
            # (do NOT retry) -- treating this as unscannable would loop forever.
            # A turn with neither text nor tool content is anomalous; fail closed
            # only when the posture asks for it.
            self._retries.pop(event.agent, None)
            if not has_tool and self.on_unscannable == "block":
                raise PrismaAirsResponseBlocked(
                    {"action": "block", "category": "unscannable"}, self._tid(), 0)
            return
        verdict = await self._run("response", [{"response": text}])
        if verdict is _UNSCANNABLE or verdict is None:  # on_error="allow" or allow
            self._retries.pop(event.agent, None)
            return
        # Block: AfterModelCallEvent can only RETRY, not substitute.
        count = self._retries.get(event.agent, 0) + 1
        if count <= self.retry_limit:
            self._retries[event.agent] = count
            self._log("response", "retry", self._tid(), 0.0,
                      verdict=verdict, note="retry %d/%d" % (count, self.retry_limit))
            event.retry = True
            return
        # Retries exhausted -- fail closed. The blocked message is discarded
        # by the framework and never added to history. `count - 1` is the number
        # of retries actually performed, which is what the caller needs to see.
        self._retries.pop(event.agent, None)
        raise PrismaAirsResponseBlocked(verdict, self._tid(), count - 1)

    async def _on_before_tool(self, event: BeforeToolCallEvent) -> None:
        tool_use = getattr(event, "tool_use", None) or {}
        name = tool_use.get("name", "tool")
        verdict = await self._scan_tool("tool_input", name, tool_use.get("input"), None)
        if verdict is _UNSCANNABLE:
            return
        if verdict is not None:  # block
            event.cancel_tool = self._reason("tool_input", verdict, tool=name)

    async def _on_after_tool(self, event: AfterToolCallEvent) -> None:
        # If before-tool cancelled this call, the tool never ran and Strands
        # fired us with a synthetic cancel result -- do not re-scan our own notice.
        if getattr(event, "cancel_message", None):
            return
        tool_use = getattr(event, "tool_use", None) or {}
        name = tool_use.get("name", "tool")
        result = getattr(event, "result", None)
        output, opaque = _classify_tool_result(result)
        # Checked before the text, exactly as the prompt leg does. A result that
        # carries an un-inspectable block ALONGSIDE text would otherwise be
        # scanned on its text alone and the block would re-enter the model; the
        # next before-model leg is no second chance, because it does not recurse
        # into a toolResult.
        if opaque and self.on_unscannable == "block":
            # A tool returned content we cannot read as text; the seat's whole
            # promise is that a tool output never re-enters the model unscanned,
            # so fail closed by replacing the result.
            self._log("tool_output", "unscannable", self._tid(), 0.0, tool_name=name,
                      note="opaque tool output")
            event.result = self._error_result(tool_use, self._reason(
                "tool_output", {"action": "block", "category": "unscannable"}, tool=name))
            return
        verdict = await self._scan_tool("tool_output", name, tool_use.get("input"), output)
        if verdict is _UNSCANNABLE or verdict is None:
            return
        # Block: AfterToolCallEvent CAN substitute -- replace the result so the
        # poisoned / leaking output never re-enters the model.
        event.result = self._error_result(tool_use, self._reason("tool_output", verdict, tool=name))

    @staticmethod
    def _error_result(tool_use, text):
        return {
            "toolUseId": tool_use.get("toolUseId", ""),
            "status": "error",
            "content": [{"text": text}],
        }

    # -- scan plumbing ----------------------------------------------------

    async def _scan_tool(self, leg, tool_name, tool_input, tool_output):
        tool_event = {
            "metadata": {"ecosystem": TOOL_ECOSYSTEM, "method": "tools/call",
                         "server_name": self.tool_server, "tool_invoked": tool_name},
            "input": _as_json(tool_input if tool_input is not None else {})}
        if tool_output is not None:
            tool_event["output"] = _as_json(tool_output)
        return await self._run(leg, [{"tool_event": tool_event}], tool_name=tool_name)

    async def _run(self, leg, contents, tool_name=None):
        api_key = os.environ.get("PRISMA_AIRS_API_KEY")
        profile = self.profile_name or os.environ.get("PRISMA_AIRS_PROFILE_NAME")
        endpoint = os.environ.get("PRISMA_AIRS_URL", DEFAULT_ENDPOINT)
        ai_profile = {}
        if self.profile_id:
            ai_profile["profile_id"] = self.profile_id
        if profile:
            ai_profile["profile_name"] = profile
        transaction_id = self._tid()
        if not api_key or not ai_profile:
            reason = "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set"
            self._log(leg, "error", transaction_id, 0.0, error=reason, tool_name=tool_name)
            return {"action": "block", "category": "airs_error", "error": reason} \
                if self.on_error == "block" else _UNSCANNABLE
        metadata = {"app_name": "%s-%s" % (APP_NAME_PREFIX, self.app_name)
                    if self.app_name else APP_NAME_PREFIX}
        if self.app_user:
            metadata["app_user"] = self.app_user
        if self.ai_model:
            metadata["ai_model"] = self.ai_model
        if self.agent_meta:
            metadata["agent_meta"] = dict(self.agent_meta)
        payload = {"transaction_id": transaction_id, "ai_profile": ai_profile,
                   "metadata": metadata, "contents": contents}
        if self.session_id:
            payload["session_id"] = str(self.session_id)
        started = time.monotonic()
        # The scan client is blocking urllib. These callbacks run on the caller's
        # event loop, so it goes to that loop's default executor: the leg still
        # awaits the verdict before returning, ordering and enforcement unchanged,
        # but nothing else on the loop is frozen for the duration of the call.
        verdict, error = await asyncio.get_running_loop().run_in_executor(
            None, _scan, endpoint, api_key, payload, self.timeout)
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
            return {"action": "block", "category": "airs_error", "error": error} \
                if self.on_error == "block" else _UNSCANNABLE
        self._log(leg, action, transaction_id, elapsed, verdict=verdict, tool_name=tool_name)
        if self.on_verdict is not None:
            try:
                self.on_verdict(leg, verdict)
            except Exception as exc:
                logger.warning("prisma_airs %s", json.dumps(
                    {"warning": "on_verdict callback failed", "error": str(exc)}))
        return verdict if action == "block" else None

    def _reason(self, leg, verdict, tool=None):
        detail = "%s scan, category=%s, scan_id=%s" % (
            leg, verdict.get("category"), verdict.get("scan_id"))
        if tool is not None:
            detail += ", tool=%s" % tool
        return "Blocked by Prisma AIRS (%s)." % detail

    def _tid(self):
        return str(uuid.uuid4())

    @staticmethod
    def _log(leg, action, transaction_id, elapsed_ms, verdict=None, error=None,
             tool_name=None, note=None):
        record = {"leg": leg, "action": action, "transaction_id": transaction_id,
                  "ms": round(elapsed_ms, 1)}
        if tool_name:
            record["tool"] = tool_name
        if note:
            record["note"] = note
        if isinstance(verdict, dict):
            record["category"] = verdict.get("category")
            record["scan_id"] = verdict.get("scan_id")
            record["report_id"] = verdict.get("report_id")
            # A verdict field of an unexpected TYPE is loggable but unreadable:
            # summarising it must never raise out of a scan decision.
            detected = {}
            for side in ("prompt_detected", "response_detected"):
                flags = verdict.get(side)
                hits = [k for k, v in flags.items() if v] if isinstance(flags, dict) else []
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
            if verdict.get("timeout"):
                record["timeout"] = True
            if verdict.get("error"):
                record["error_flag"] = True
        if error is not None:
            record["error"] = error
        line = "prisma_airs %s" % json.dumps(record)
        (logger.info if action in ("allow", "retry") else logger.warning)(line)


class _Unscannable:
    """Sentinel: allow this leg through without a verdict (on_unscannable=allow)."""


_UNSCANNABLE = _Unscannable()


def _classify_tool_result(result):
    """(text, opaque). text is the scannable text/json of a ToolResult; opaque is
    True when the result carries a block that cannot be read as text -- so the
    after-tool leg fails closed rather than passing it through unscanned.

    The member list is an allowlist: `text` and `json` are the two text-bearing
    members of a ToolResult, and everything else -- document, image, video, or a
    member added to the framework after this file was written -- is opaque. A
    block type this seat has never heard of must fail closed, not vanish."""
    if not isinstance(result, dict):
        return None, False
    content = result.get("content")
    if content is None:
        return None, False
    if not isinstance(content, (list, tuple)):
        return None, True  # not a content list at all -- unreadable, fails closed
    parts, opaque = [], False
    for block in content:
        if not isinstance(block, dict):
            opaque = True
        elif isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif "json" in block:
            parts.append(json.dumps(block["json"], default=str))
        else:
            # document, image, video, or a member added to the framework after
            # this file was written -- not readable as text, so it fails closed.
            opaque = True
    return ("\n".join(parts) if parts else None), opaque


def _as_json(value):
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)
