# Amazon Bedrock AgentCore Integration with Prisma AIRS

A guard for agents running on Amazon Bedrock AgentCore Runtime that scans all **four legs** of the agent loop with Palo Alto Networks Prisma AI Runtime Security (AIRS): the prompt going to the model, the model's response, and -- the seat's whole reason for existing -- **each tool call's input and output as first-class `tool_event`s**. A poisoned tool result or a credential leaked by an external system is caught here, before it re-enters the model, where no SDK-client hook can see it.

One file, standard library only. AgentCore runs Python; your agent brings its own model SDK, the guard brings nothing.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | `scan_prompt()` before the model call; a blocked prompt raises before the model is invoked |
| Response | ✅ | `scan_response()` after the model call, with the prompt as context |
| Streaming | ⚠️ | Non-streamed model calls are fully covered; for a streamed response, scan each buffered chunk or the assembled text (you control the loop, so you choose the granularity) |
| Pre-tool call | ✅ | `scan_tool_input()` before a tool runs -- the input is sent as a `tool_event` |
| Post-tool call | ✅ | `scan_tool_output()` before the result re-enters the model -- the leg where injected tool results and leaked credentials are caught |

This is the only AWS integration that scans tool calls as tool calls. It is the deepest of the four and the narrowest in fit: you place the calls, and only the loop you instrument is covered.

## Architecture

**Where it stands**

```mermaid
flowchart TB
    U["Invocation payload"]
    subgraph rt["AgentCore Runtime (your entrypoint)"]
        direction TB
        P["scan_prompt"]
        M["model call (Bedrock)"]
        R["scan_response"]
        TI["scan_tool_input"]
        T["tool executes"]
        TO["scan_tool_output"]
        P --> M --> R
        M -.tool use.-> TI --> T --> TO -.result.-> M
    end
    AIRS["Prisma AIRS<br/>/v1/scan/sync/request"]
    U --> P
    P <-.-> AIRS
    R <-.-> AIRS
    TI <-.-> AIRS
    TO <-.-> AIRS
    classDef airs fill:#FA582D,stroke:#C93F1A,color:#fff
    classDef seat fill:#1a7f37,stroke:#116329,color:#fff
    class AIRS airs
    class P,R,TI,TO seat
```

**A guarded tool call**

```mermaid
sequenceDiagram
    autonumber
    participant L as Agent loop
    participant G as PrismaAirsGuard
    participant A as Prisma AIRS
    participant T as Tool (external system)
    participant M as Model

    L->>G: scan_tool_input(name, args)
    G->>A: tool_event {input}
    A-->>G: allow
    G->>T: (loop runs the tool)
    T-->>L: result (may be attacker-influenced)
    L->>G: scan_tool_output(name, args, result)
    G->>A: tool_event {input, output}
    alt tool result is poisoned / leaks a secret
        A-->>G: block (context poisoning / credential leakage)
        G-->>L: raise PrismaAirsBlocked
        Note over M: the poisoned result never re-enters the model
    else clean
        A-->>G: allow
        G-->>L: return; result feeds back to the model
    end
```

## Why a guard, not a hook

The SDK-client hooks intercept a client. An AgentCore agent is *your* loop -- the runtime hosts the code you wrote, and there is no universal seam to intercept an arbitrary agent loop. So the integration is a guard you call at the four legs. That explicitness is also its strength: it is the only seat positioned to treat a tool call as a `tool_event`, which is what lets AIRS return a tool-specific verdict (`context poisoning`, `credential leakage`) instead of seeing the tool result merely as text in the next prompt.

The guard reads the AgentCore request id and session id from the runtime context automatically (so a scan in Strata Cloud Manager lines up with an invocation in the AgentCore logs), and derives the runtime's agent ARN from its OTEL resource attributes into `metadata.agent_meta.agent_arn` -- pass `agent_arn=` only to override or when running off-runtime.

## Setup

### Prerequisites

- Prisma AIRS API key and security profile ([Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com))
- An agent on Amazon Bedrock AgentCore Runtime (Python 3.9+, standard library only)

### Installation

Copy [`prisma_airs_agentcore.py`](./prisma_airs_agentcore.py) into your agent's deployment package and place the guard in your loop:

```python
from prisma_airs_agentcore import PrismaAirsGuard, PrismaAirsBlocked

guard = PrismaAirsGuard(app_name="support-agent", agent_arn=MY_AGENT_ARN)

try:
    guard.scan_prompt(user_text)
    reply = model_call(user_text)
    guard.scan_response(reply, prompt=user_text)
except PrismaAirsBlocked as blocked:
    return safe_refusal(blocked)
```

Or wrap a tool so both tool legs are automatic:

```python
@guard.guard_tool(server_name="crm")
def lookup_ticket(ticket_id: str) -> dict:
    ...
```

The wrapper matches the tool it decorates. An `async def` tool is wrapped by an `async def` wrapper that awaits the tool before scanning its output -- and runs the scan itself in a worker thread, so the runtime's event loop keeps serving while AIRS is called. A generator or async-generator tool is wrapped by a generator of the same kind that drains the tool and scans the whole output before yielding the first item. In every shape the output leg scans a materialized result, never a coroutine or a generator object.

See [`examples/agent_entrypoint.py`](./examples/agent_entrypoint.py) for a complete guarded Converse tool loop.

### Configure environment

| Variable | Required | Description |
|----------|----------|-------------|
| `PRISMA_AIRS_API_KEY` | yes | API key from Strata Cloud Manager |
| `PRISMA_AIRS_PROFILE_NAME` | yes | AIRS security profile name (or pass `profile_name=` / `profile_id=`) |
| `PRISMA_AIRS_URL` | no | EU endpoint if needed; defaults to US. HTTPS enforced, redirects refused |

### Verify

```bash
cp examples/env.example .env   # fill in, then:  set -a; source .env; set +a
python3 scripts/validate.py
```

Ten checks against the live API -- **no AWS account or AgentCore runtime required**: the four legs are plain scan calls, exercised as the loop would call them.

## Configuration

```python
PrismaAirsGuard(
    app_name="support-agent",  # -> metadata.app_name = "AWS-AgentCore-support-agent"
    profile_name=None,         # overrides PRISMA_AIRS_PROFILE_NAME
    profile_id=None,           # AI profile UUID
    agent_arn=None,            # -> metadata.agent_meta.agent_arn (auto-derived on-runtime)
    agent_id=None,             # -> metadata.agent_meta.agent_id
    agent_version=None,        # -> metadata.agent_meta.agent_version
    app_user=None,             # -> metadata.app_user
    ai_model=None,             # -> metadata.ai_model
    on_error="block",          # "block" | "allow" when AIRS is unreachable / errors
    on_unscannable="block",    # "block" | "allow" when there is no text to scan
    strict_verdict=False,      # treat a detection-service timeout/error as on_error
    on_verdict=None,           # callable(leg, verdict) observer for every scan
    timeout=10.0,              # seconds per scan call
)
```

Every `scan_*` method returns the verdict dict on allow and raises `PrismaAirsBlocked` (carrying `leg`, `verdict`, `transaction_id`) on block. `guard_tool()` binds a tool's arguments to their parameter names before scanning, so the input reads as data rather than as call structure.

**Fail-closed by default.** Missing credentials, an unreachable or erroring AIRS API, a scan that exceeds its `timeout`, and a verdict without an `action` all block unless you choose `on_error="allow"`.

**Empty content follows `on_unscannable` on the model legs**, and each leg is judged on its own field: an empty prompt blocks `scan_prompt()`, and an empty model turn blocks `scan_response()` even when a prompt is passed as context. The **tool legs always scan whatever the tool call carries** -- a `tool_event` still names the tool and its server, so a tool that legitimately takes no arguments or returns nothing is scanned, not blocked. The one exception there is a tool result the guard cannot materialize -- a coroutine or a generator handed back in place of a value: that is unscannable output and follows `on_unscannable` rather than being scanned as a placeholder.

## Logging

One line per leg, `INFO` for allows and for unscannable content the posture lets through, `WARNING` for blocks and errors, carrying the leg, `transaction_id`, and -- for tool legs -- the tool name, tool verdict, and threat list:

```
[WARNING] prisma_airs {"leg": "tool_output", "action": "block", "transaction_id": "...", "ms": 631.0, "tool": "read_ticket", "tool_verdict": "malicious", "category": "malicious", "scan_id": "...", "report_id": "R...", "detected": {"tool_threats": ["context poisoning"]}}
```

## Testing

```bash
python3 scripts/validate.py
```

Ten live-API checks across the four legs: benign prompt allowed, injection prompt blocked (before-model), leaking response blocked (after-model), benign tool input allowed (before-tool), **poisoned tool output blocked as context poisoning and a credential-leaking tool output blocked (after-tool)** -- the legs unique to this seat -- the `guard_tool` wrapper firing both tool legs, and fail-closed behavior on an unreachable endpoint.

## Limitations

- **You place the calls.** Unlike the SDK hooks, nothing is automatic beyond the tools you wrap with `guard_tool`. A leg you do not call is a leg not scanned. (This is inherent: there is no interception seam for an arbitrary agent loop.)
- **Tool ecosystem.** The scan API accepts one tool ecosystem today, `mcp`; the guard sends that value for every tool leg. Tool events are still scanned for any Python tool, MCP-based or not -- the field is a protocol label, not a gate on your tool implementation.
- **A source-code detector will fire on tool input.** `tool_event.input` is a serialized JSON object by construction, and on a profile with the source-code detector enabled that shape can be flagged on its own merits -- a tool called with arguments as ordinary as `{"x": "x"}` is enough. The input leg then blocks before the tool runs, so the output leg never happens and a benign tool call is denied. This is the profile's policy rather than a fault in the guard, but it makes such a profile unsuitable for agentic tool scanning: use a profile without that detector for the tool legs, or scan tool output only. The validation harness reports this case as a profile-dependent warning rather than a failure.
- **Streaming.** For a streamed model response you choose when to scan (per buffered chunk or on the assembled text); the guard does not intercept the stream for you.
- **Generator tools are buffered.** `guard_tool` drains a generator or async-generator tool and scans its complete output before yielding the first item -- one scan for the whole output rather than one per item. Both tool legs therefore fire when the generator is first iterated, and an unbounded generator cannot be guarded this way: scan such a stream yourself with `scan_tool_output()` per buffered chunk.
- **A scan is a blocking call.** The async wrappers offload it to a worker thread so the runtime's event loop keeps serving; a sync tool's scan blocks the calling thread for its duration.
- **Lazy tool results.** A tool that *returns* a coroutine or a generator rather than a value has produced nothing to scan, so `guard_tool` treats it as unscannable output and blocks by default -- return a materialized value, or scan the drained result yourself. Other lazy iterators (`map`, `filter`, `itertools`, a custom `__iter__`) are not recognized as lazy and are serialized as they stand, which for most of them means their `repr`; materialize those in the tool.
- **Latency.** Each leg adds one scan call; a tool round adds two (input + output). `timeout=` bounds the connect and, separately, the response read -- the body is taken one socket read at a time against a wall-clock deadline, so a peer that trickles bytes costs at most about twice `timeout` rather than stalling the caller indefinitely -- and a scan response is capped at 10 MB; exceeding either follows the `on_error` posture. Budget accordingly.

## Resources

- [Prisma AIRS API Reference](https://pan.dev/airs/)
- [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/)
- [Prisma AIRS tool_event scanning](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/)
- [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
