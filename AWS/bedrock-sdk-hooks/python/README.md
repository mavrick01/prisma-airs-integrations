# Amazon Bedrock boto3 Hook Integration with Prisma AIRS

A handler for the botocore event system that scans **every Amazon Bedrock model invocation** made through a protected client with Palo Alto Networks Prisma AI Runtime Security (AIRS) -- including calls a framework (LangChain, LlamaIndex, an agent SDK) makes on the application's behalf. A blocked prompt never leaves the process: the request is intercepted **before it is signed or sent**, so nothing reaches AWS and nothing is billed.

One file, standard library + botocore (which boto3 always brings). Covers `Converse`, `ConverseStream`, `InvokeModel`, and `InvokeModelWithResponseStream`.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Every model call through the client is scanned pre-flight; a blocked prompt is never signed, sent, or billed |
| Response | ✅ | `Converse` and `InvokeModel` responses are scanned (and can be rewritten or masked) before the application sees them |
| Streaming | ⚠️ | The prompt leg of `ConverseStream` / `InvokeModelWithResponseStream` is fully scanned; the streamed response itself is not (it is still on the wire when the hook runs) |
| Pre-tool call | ❌ | There is no tool leg at this seat. Tool use rides inside message content: a `toolUse` block is walked as text on the response leg (tool name + serialized arguments), but it gets a response verdict, not a tool verdict -- the agent-loop integrations own that leg |
| Post-tool call | ❌ | Same -- a `toolResult` is walked as text on the prompt leg of the next request that carries it, not as a `tool_event` with its own verdict |

## Architecture

**Where it stands**

```mermaid
flowchart LR
    APP["Application code"]
    FW["Framework / agent SDK<br/>calls made on your behalf"]
    subgraph client["boto3 bedrock-runtime client"]
        HOOK["botocore event handlers<br/>before-call &middot; after-call"]
    end
    AIRS["Prisma AIRS<br/>/v1/scan/sync/request"]
    BR["Amazon Bedrock"]
    APP --> HOOK
    FW --> HOOK
    HOOK <-. "scan prompt&nbsp;&middot;&nbsp;scan response" .-> AIRS
    HOOK --> BR
    classDef airs fill:#FA582D,stroke:#C93F1A,color:#fff
    classDef seat fill:#1a7f37,stroke:#116329,color:#fff
    class AIRS airs
    class HOOK seat
```

**The request lifecycle**

```mermaid
sequenceDiagram
    autonumber
    participant APP as Application
    participant B as botocore
    participant A as Prisma AIRS
    participant AWS as Amazon Bedrock

    APP->>B: converse / invoke_model
    B->>A: before-call: scan prompt
    alt action = block
        A-->>B: block verdict
        B-->>APP: raise PrismaAirsBlocked / shaped block response
        Note over AWS: request never signed, never sent, never billed
    else action = allow
        A-->>B: allow
        B->>AWS: sign + send (botocore's normal path, retries intact)
        AWS-->>B: response
        B->>A: after-call: scan response (prompt as context, when scan_prompt is on)
        alt action = block
            A-->>B: block verdict
            B-->>APP: raise / response text replaced
        else action = allow
            A-->>B: allow
            B-->>APP: response (masked, if the profile masks DLP hits)
        end
    end
```

## Why this seat

A Bedrock guardrail is a **request parameter**: every call site must remember to pass `guardrailIdentifier`, and a call without it -- a new code path, a framework internal, a developer shortcut -- is silently unguarded. A botocore handler is registered **on the client**: every call through it is scanned, whoever makes it. The two compose well; this integration is the safety net under whatever else is configured.

The interception uses botocore's own extension seams, not monkey-patching: `before-call` handlers may return a response, which short-circuits the request machinery entirely (no signing, no network, no retry loop), and `after-call` handlers may rewrite the parsed response in place -- the same mechanism botocore itself uses for response post-processing.

## Setup

### Prerequisites

- Prisma AIRS API key and security profile ([Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com))
- Python 3.9+ with boto3

### Installation

Copy [`prisma_airs_boto3_hook.py`](./prisma_airs_boto3_hook.py) next to your application code and protect the client (or a whole session):

```python
import boto3
from prisma_airs_boto3_hook import protect_client, protect_session

bedrock = protect_client(boto3.client("bedrock-runtime"), app_name="support-chat")

# or: every bedrock-runtime client later created from this session is protected
session = protect_session(boto3.Session(), app_name="support-chat")
```

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

Eleven live-API checks -- **no AWS credentials needed**: a blocked call short-circuits before signing, so the whole block path is proven through a real client with placeholder credentials. See [Testing](#testing).

## Configuration

```python
protect_client(client,
    app_name="support-chat",   # -> metadata.app_name = "AWS-Bedrock-support-chat"
    profile_name=None,         # overrides PRISMA_AIRS_PROFILE_NAME
    profile_id=None,           # AI profile UUID; name or id must resolve
    session_id=None,           # conversation id for SCM session correlation
    app_user=None,             # end-user identity for metadata.app_user
    on_block="raise",          # "raise" PrismaAirsBlocked | "respond" with a shaped block reply
    on_verdict=None,           # callable(leg, verdict) observer for every scan
    on_error="block",          # "block" | "allow" when AIRS is unreachable / errors
    on_unscannable="block",    # "block" | "allow" for content that cannot be read as text
    strict_verdict=False,      # treat detection-service timeout/error as on_error
    apply_masked_data=False,   # masked text replaces the response on mask-and-allow profiles
    scan_prompt=True,
    scan_response=True,
    timeout=10.0,              # seconds per scan (two scans per round trip)
)
```

**What gets scanned.** For `Converse`/`ConverseStream`, the prompt leg covers **the system prompt plus every user-role message** (a single call can smuggle instructions in any of them); the response leg covers the assistant message. Both legs walk the content blocks the same way: `text`, `guardContent` text, `toolResult` text and JSON, `toolUse` (tool name plus serialized arguments -- model-emitted arguments are text the application is about to act on), `reasoningContent` reasoning text, `searchResult` passages, and `citationsContent` answer and cited source text. The walker is an **allowlist with a fail-closed default**: documents, images, video, audio, redacted reasoning, and any block shape it does not recognize are flagged unscannable rather than skipped. That catches a Bedrock content type added after this file was written, and it also catches current members the walker does not extract -- notably the dynamic tool-management blocks `toolAddition` and `toolRemoval`, whose tool specifications are real text this seat does not scan. Unscannable content follows the `on_unscannable` posture **on the prompt leg** (blocked by default; set `"allow"` for multimodal apps and for agents that add or remove tools mid-conversation, and pair with deeper controls); on the response leg the posture applies only to a reply with no extractable text at all, as described under [Limitations](#limitations). The one recognized block that is neither extracted nor flagged is a well-formed `cachePoint` -- a caching marker whose only members are `type` and `ttl` and which delivers no content to the model; a `cachePoint` carrying anything else is unscannable like any other unrecognized shape.

For `InvokeModel`, the known body dialects are extracted precisely -- the messages dialect (both the Converse-shaped and the type-tagged form, walking `tool_result`, `tool_use` and thinking blocks on both legs), Amazon Nova/Titan, Meta, Mistral, and Cohere (newest message plus `chat_history`, `documents`, and `tool_results`) -- and **unknown dialects fall back to scanning the entire serialized body**, so unknown models err toward inspecting too much rather than too little. A body that is partly recognized but carries something the walker cannot read is reported unscannable instead of being scanned in part. `metadata.ai_model` is stamped automatically from the request's model id on both scan legs, and `transaction_id` is generated per call and echoed in the verdict.

**Two blocking styles.** `on_block="raise"` (default) raises `PrismaAirsBlocked` carrying the leg, verdict, and transaction id. `on_block="respond"` delivers a well-formed response instead -- a `content_filtered` Converse reply on either leg, a JSON body for `InvokeModel`, or a minimal valid event stream for the two streaming operations -- whose text states the block, with the verdict attached under `ResponseMetadata.PrismaAirs`, for callers that cannot be taught a new exception. A blocked Converse reply carries `stopReason: "content_filtered"`, so an agent loop that branches on `stopReason` is not left hunting for a tool call that was withheld.

**Registering twice is a no-op.** Protecting the same client or session twice registers one set of handlers, never a double scan -- and so does protecting a client that was created from an already protected session, which keeps the session's configuration rather than adding a second, differently configured scan to every call.

**Error responses pass through.** An AWS error (throttle, auth failure, validation error) carries no model output; the hook steps aside so botocore raises the genuine exception instead of masking it with a scan verdict.

**Fail-closed by default.** Missing credentials, an unreachable or erroring AIRS API, a verdict without an `action`, and unextractable content all block unless `on_error="allow"` / `on_unscannable="allow"` is chosen explicitly. A malformed body or response the extractor cannot walk is treated as unscannable and follows the same posture -- extraction never raises out of your `converse()` or `invoke_model()` call.

## Logging

One line per scan leg, `INFO` for allows and neutral outcomes (stream-response skips, masking applied) and `WARNING` for blocks and errors, carrying the operation name, `transaction_id`, detection flags, and latency:

```
[WARNING] prisma_airs {"leg": "prompt", "action": "block", "transaction_id": "b7dd...", "ms": 522.4, "operation": "Converse", "category": "malicious", "scan_id": "...", "detected": {"prompt_detected": ["injection"]}}
```

## Testing

```bash
# Core checks against the live AIRS API -- no AWS account or credentials
python3 scripts/validate.py

# Also run real Bedrock round trips (needs AWS credentials + model access)
python3 scripts/validate.py --bedrock
```

The core run proves: injection blocked before signing (through a real client whose placeholder credentials would fail if the request were ever sent), the shaped-response block style, InvokeModel dialect extraction, the unknown-dialect fallback, benign traffic passing through to AWS's own machinery, fail-closed behavior with an unreachable endpoint, and session-id echo.

## Limitations

- **Streamed responses are not scanned.** For the two streaming operations the response is still on the wire when `after-call` fires; only their prompt leg is scanned. Buffer-then-scan proxies (an AI gateway) are the pattern when streamed output must be enforced.
- **Tool calls are not scanned as tool events.** At this seat, tool use and tool results are content inside messages: they are scanned as text on the leg that carries them (a `toolUse` on the response leg, a `toolResult` on the next prompt leg), so they get a message verdict rather than a tool verdict, and enforcement lands on the whole call. The agent-loop integrations ([bedrock-agentcore](../../bedrock-agentcore/), [strands-agents](../../strands-agents/)) scan them as first-class `tool_event` payloads.
- **Assistant-role turns and tool specifications are not scanned.** The prompt leg covers the system prompt and user-role messages. Assistant-role turns replayed from a datastore, constructed by the application, or appended after a streamed reply are delivered to the model unscanned, as is `toolConfig.tools[].toolSpec` (name, description, input schema), which Bedrock renders into the model's context. Prior assistant turns are covered only where they were produced through this same protected client on a non-streaming operation.
- **The response leg blocks on "no text", not on "some opaque content".** A response that carries no extractable text at all follows `on_unscannable`; one that mixes text with a block the walker cannot inspect is scanned on its text. The request leg applies the posture to both cases.
- **Masking substitutes into text blocks.** With `apply_masked_data=True`, the masked text replaces the Converse response's text blocks in place and every other block is left untouched, so an allowed tool-calling turn keeps its `toolUse`. AIRS masks the whole joined extraction, so on a multi-block reply the first text block receives the masked form of everything that was scanned -- tool name and arguments, reasoning, and cited source text included -- while those other blocks keep the model's own, unmasked text. A response with no text block at all cannot carry the substitution -- it follows the block path instead. For `InvokeModel` the masked text is delivered in a `{"prisma_airs": "response replaced", "text": ...}` envelope rather than re-encoded into the model family's own dialect.
- **This client only.** The hook protects clients it is registered on (or created from a protected session). Other clients, other processes, other languages, and raw HTTPS calls to Bedrock are not covered -- for fleet-wide enforcement, combine with network-layer inspection.
- **Latency.** Two sequential scans per round trip; each bounded by `timeout=` (default 10 s) as a socket timeout on connect and as a wall-clock deadline over the response body read, with timeouts following the `on_error` posture. Scan responses larger than 10 MB are refused.
- **Unknown InvokeModel dialects** are scanned as raw serialized JSON -- detection quality on structure-heavy bodies may differ from clean extracted text.

## Resources

- [Prisma AIRS API Reference](https://pan.dev/airs/)
- [Amazon Bedrock Runtime API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_Operations_Amazon_Bedrock_Runtime.html)
- [botocore event system](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/events.html)
- [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
