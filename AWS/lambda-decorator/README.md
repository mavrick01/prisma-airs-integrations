# AWS Lambda Handler Decorator with Prisma AIRS

A Python decorator that scans the prompt entering, and the response leaving, any AI handler hosted on AWS Lambda with Palo Alto Networks Prisma AI Runtime Security (AIRS). It stands at the **function boundary**: it works with any model provider the handler calls (Amazon Bedrock, OpenAI, self-hosted, or anything else) and any framework, because it never looks inside the handler -- it guards the door.

One file, standard library only. No Lambda layer, no `requirements.txt`, any `python3.x` runtime.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Scans the extracted prompt before the handler body runs; a blocked prompt never reaches the handler or the model behind it |
| Response | ✅ | Scans the handler's returned text before Lambda returns it; a blocked response is withheld, and DLP-masked output can replace the original (`apply_masked_data=True`) |
| Streaming | ❌ | Python Lambda handlers return complete payloads (response streaming is a Node.js runtime feature), so there is no stream to intercept -- and nothing is buffered that was not already buffered |
| Pre-tool call | ❌ | Tool calls happen inside the handler, below the function boundary; use the Bedrock or agent-framework integrations for tool visibility |
| Post-tool call | ❌ | Same -- invisible from the boundary |

## Architecture

**Where it stands**

```mermaid
flowchart LR
    subgraph callers["Callers"]
        direction TB
        GW["API Gateway / ALB"]
        EV["SQS / SNS / EventBridge"]
        DI["Direct invoke"]
    end
    subgraph fn["AWS Lambda function"]
        direction TB
        DEC["@airs_protect<br/>function boundary"]
        H["handler&nbsp;&mdash;&nbsp;your code<br/>any model, any SDK"]
        DEC --> H
    end
    AIRS["Prisma AIRS<br/>/v1/scan/sync/request"]
    M["Model provider<br/>Amazon Bedrock or any other"]
    GW --> DEC
    EV --> DEC
    DI --> DEC
    DEC <-. "scan prompt&nbsp;&middot;&nbsp;scan response" .-> AIRS
    H --> M
    classDef airs fill:#FA582D,stroke:#C93F1A,color:#fff
    classDef seat fill:#1a7f37,stroke:#116329,color:#fff
    class AIRS airs
    class DEC seat
```

**The request lifecycle**

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant D as @airs_protect
    participant H as handler
    participant A as Prisma AIRS

    C->>D: event
    D->>A: scan prompt (transaction_id = request id)
    alt action = block
        A-->>D: block verdict
        D-->>C: HTTP 403 / raise PrismaAirsBlocked
        Note over H: the handler never runs -- the model behind it is never invoked
    else action = allow
        A-->>D: allow
        D->>H: event, context
        H-->>D: result
        D->>A: scan response (prompt + response together)
        alt action = block
            A-->>D: block verdict
            D-->>C: reply withheld -- HTTP 403 / raise
        else action = allow
            A-->>D: allow
            D-->>C: result (masked, if the profile masks DLP hits)
        end
    end
```

The trade this seat makes: **maximum reach, minimum depth.** Every Lambda-hosted AI app can wear this decorator unchanged, but the decorator sees only what crosses the boundary -- one prompt in, one response out. An agent loop running inside the handler (model calls, tool calls) is invisible to it. If you need those legs, pair or replace it with the deeper integrations in this directory.

Blocking has two shapes because Lambda has two caller worlds. HTTP proxy events (API Gateway, ALB) get an HTTP **403** with the scan verdict in the body -- recognised from the proxy envelope itself (`httpMethod`, `routeKey`, `requestContext.http`, `requestContext.elb`, `version: "2.0"`), so a bodyless HTTP API request such as a `GET` route or a CORS preflight is still answered with the 403 rather than an error the gateway renders as a 5xx. Everything else -- direct invoke, SQS, SNS, EventBridge, S3 -- gets a **raised `PrismaAirsBlocked`**, because an async event source treats any returned value as success and would silently delete the blocked message; an error engages Lambda's retry, DLQ, and failure-destination semantics instead.

Two conventions this integration follows:

- `transaction_id` is set to the Lambda **request id** (`context.aws_request_id`), so a scan in Strata Cloud Manager matches a request in CloudWatch one-to-one. (This is the current name of the legacy `tr_id` field, which the service still honors but is retiring.)
- `app_name` is `AWS-Lambda-<your-app>` -- the integration identifies itself and you append your application via `app_name=`.

## Setup

### Prerequisites

- Prisma AIRS API key and security profile ([Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com))
- Python 3.9+ Lambda runtime (uses only the standard library)

### Installation

Copy [`prisma_airs_decorator.py`](./prisma_airs_decorator.py) into your deployment package next to your handler and decorate it:

```python
from prisma_airs_decorator import airs_protect

@airs_protect(app_name="support-chat")
def handler(event, context):
    ...
```

### Configure environment

Set on the Lambda function (Configuration > Environment variables):

| Variable | Required | Description |
|----------|----------|-------------|
| `PRISMA_AIRS_API_KEY` | yes | API key from Strata Cloud Manager |
| `PRISMA_AIRS_PROFILE_NAME` | yes | AIRS security profile name (or pass `profile_name=` / `profile_id=` in code) |
| `PRISMA_AIRS_URL` | no | `https://service.api.eu.aisecurity.paloaltonetworks.com` for EU; defaults to US. HTTPS is enforced, and redirects are refused so the API key can never travel to another host |

Plain environment variables are readable by anyone with `lambda:GetFunctionConfiguration`. For production, store the key in AWS Secrets Manager and export it into the environment at cold start -- the decorator only requires that `PRISMA_AIRS_API_KEY` is present in `os.environ` by the time a request arrives.

### Verify

```bash
cp examples/env.example .env   # fill in, then:  set -a; source .env; set +a
python3 scripts/validate.py
```

Nine live-API checks across six scenarios: benign traffic passes, an injection prompt is blocked **before** the handler runs (and the handler provably never runs), a leaking response is withheld, an unreadable event fails closed without spending a scan, an unreachable AIRS endpoint blocks by default with `on_error="allow"` as the explicit opt-out, and `transaction_id`/`session_id` round-trip into the verdict. See [Testing](#testing).

## Configuration

Every parameter maps to a field of the scan API's request or verdict; the decorator sends everything the platform can know and reads everything the verdict can say.

```python
@airs_protect(
    # identity & profile
    app_name="support-chat",        # -> metadata.app_name = "AWS-Lambda-support-chat"
    profile_name=None,              # overrides PRISMA_AIRS_PROFILE_NAME
    profile_id=None,                # AI profile UUID; name or id must resolve

    # extractors: point each at what your handler actually reads/writes
    prompt_from=None,               # callable(event)  -> str | SKIP | None
    response_from=None,             # callable(result) -> str | SKIP | None
    session_id_from=None,           # callable(event, context) -> str   (session_id)
    app_user_from=None,             # callable(event, context) -> str   (metadata.app_user)
    user_ip_from=None,              # callable(event, context) -> str   (metadata.user_ip;
                                    #   default auto-reads API GW v1/v2 sourceIp / X-Forwarded-For)
    context_from=None,              # callable(event)  -> str  (contents.context, grounding)
    code_prompt_from=None,          # callable(event)  -> str  (contents.code_prompt)
    code_response_from=None,        # callable(result) -> str  (contents.code_response)

    # static metadata
    ai_model="us.amazon.nova-lite-v1:0",   # metadata.ai_model (string or callable(event, context))
    agent_meta=None,                # metadata.agent_meta dict (agent_id/version/arn) -- for
                                    #   agent workloads; a plain Lambda is not an AI agent

    # verdict handling
    on_block=None,                  # callable(leg, verdict, event, context) -> return value
    on_verdict=None,                # callable(leg, verdict) observer for EVERY scan verdict
    on_error="block",               # "block" | "allow" when AIRS is unreachable / errors
    on_unscannable="block",         # "block" | "allow" when no text can be extracted
    strict_verdict=False,           # True: a verdict with detection-service timeout/error
                                    #   follows on_error even if action says allow
    apply_masked_data=False,        # True: response_masked_data REPLACES the response text
    response_write=None,            # callable(result, masked_text) -> result, for custom shapes;
                                    #   required with a custom response_from when masking

    # toggles
    scan_prompt=True,
    scan_response=True,
    timeout=10.0,                   # seconds per scan (two scans per invocation)
)
```

**Extractors.** The default extractors understand API Gateway (REST and HTTP APIs), ALB proxy events, and plain direct-invoke payloads: they parse the JSON body (base64-decoded when the envelope flags it, on **both** legs; a flagged body that does not decode to UTF-8 text -- gzip, images, any binary media type -- is reported unscannable and follows `on_unscannable` instead of being scanned as its base64 wrapper) and take the first non-empty string among `prompt`, `message`, `input`, `query`, `question`, `text` (responses: `response`, `completion`, `output`, `answer`, `reply`, `message`, `text`). For your own event shapes, pass `prompt_from=` / `response_from=` pointed at **the same field your handler reads** -- then the scanner sees exactly what the application sees and a renamed field cannot slip past one but not the other. Return the module's `SKIP` sentinel to declare "nothing to scan here on purpose" (health checks, error routes) without tripping the fail-closed posture; handler results with `statusCode >= 400` are treated that way automatically.

**Fail-closed by default.** Missing credentials, an unreachable or erroring AIRS API, a non-HTTPS endpoint, a 200 response that carries no `action` verdict, and an event the extractor cannot read all *block* unless you explicitly choose `on_error="allow"` / `on_unscannable="allow"`. A security control that quietly waves traffic through when misconfigured is worse than one that fails loudly on the first test. `strict_verdict=True` extends this to degraded scans -- a verdict whose detection services report trouble (the `timeout`/`error` flags, an `error`/`timeout` category, or a populated per-service `errors` array) is then not accepted as proof of clean content, and the log line names the detector that degraded.

**Masking.** When the profile masks DLP hits instead of blocking, the verdict carries `response_masked_data`; with `apply_masked_data=True` the masked text replaces the handler's response. The default writer handles the same shapes as the default extractors and re-wraps an `isBase64Encoded` body the way it arrived, and every substitution is then **verified through the extractor**: the rewritten result is re-read, and unless the field the extractor reads now holds the masked text the response is withheld rather than leaked. For the same reason a custom `response_from=` must be paired with `response_write=` -- the decorator will not guess which field a custom reader chose, because a wrong guess would leave the sensitive original exactly where the application reads it.

**Sessions & users.** Wire `session_id_from` to your conversation or job id and every scan of that session correlates in Strata Cloud Manager; `app_user_from` (e.g. a JWT claim from the API Gateway authorizer) attributes traffic to the end user, and `user_ip` is auto-extracted from the request context.

**Not sent, on purpose:** `contents.tool_event`. Nothing at the function boundary can see a tool call; that field belongs to the agent-loop integrations ([bedrock-agentcore](../bedrock-agentcore/), [strands-agents](../strands-agents/)).

## Logging

One line per scan leg to CloudWatch -- `INFO` for allows and the other neutral outcomes (an intentional `SKIP`, an applied mask, unscannable content under `on_unscannable="allow"`) and `WARNING` for blocks and errors -- always carrying the `transaction_id` (= Lambda request id) and, when present, `session_id`, detection flags, masking flags, per-service `timeout`/`error` status, and blocked-topic / toxic-category details:

```
[WARNING] prisma_airs {"leg": "prompt", "action": "block", "transaction_id": "9f61...", "ms": 412.7, "category": "malicious", "scan_id": "...", "report_id": "R...", "detected": {"prompt_detected": ["agent", "injection"]}}
```

The DLP mask path writes two lines: the allow verdict (carrying `"masked": true`), then the `masked` line recording that the substitution was written back -- or `mask-unappliable` at `WARNING` when it could not be and the response was withheld. A custom `prompt_from`/`response_from` that raises also writes two: the `extract-error` line, then the `unscannable` outcome that extraction failure degrades to.

CloudWatch Logs Insights:

```
fields @timestamp, @message | filter @message like /prisma_airs/ | sort @timestamp desc
```

## Testing

```bash
# Local, in-process, against the live AIRS API -- no AWS account needed
python3 scripts/validate.py

# Also drive the examples/handler_bedrock_apigw.py example through real Bedrock
python3 scripts/validate.py --bedrock

# Deploy a real Lambda (airsaws-decorator-demo), invoke clean + attack, then clean up
scripts/deploy_demo.sh
scripts/teardown_demo.sh
```

The demo scripts create two `airsaws-`-prefixed resources (plus the log group Lambda creates implicitly on first invoke); the teardown removes all three and refuses to delete anything not carrying the `airsaws-` prefix.

## Limitations

- **Blind below the boundary.** Model calls, tool calls, and agent loops inside the handler are invisible; only the final prompt/response crossing the function boundary is scanned. For per-model-call or per-tool-call scanning, see the [bedrock-sdk-hooks](../bedrock-sdk-hooks/), [bedrock-agentcore](../bedrock-agentcore/), and [strands-agents](../strands-agents/) integrations.
- **The extractor must mirror the handler.** If the handler reads a field the extractor does not, the scan can see different text than the application. Set `prompt_from=`/`response_from=` to the handler's own fields; the defaults fail closed when they find nothing, so a mismatch surfaces on the first test rather than becoming a silent bypass.
- **Latency.** Two sequential scan calls are added to every invocation (measure with `scripts/validate.py`, which prints round-trip times). Size the Lambda timeout for handler time plus two scans; each scan is additionally capped by `timeout=` (default 10 s), which bounds the response-body read with a real wall-clock deadline instead of a per-read timeout a trickling peer can keep restarting; the connect and header phases remain bounded per socket read. A verdict body larger than 10 MB is refused. A timeout follows the `on_error` posture.
- **Large payloads are not truncated.** Content is sent to AIRS as-is; if the API rejects an oversized payload the result follows `on_error` (blocked, by default).
- **Binary and compressed proxy bodies carry no text to scan.** A body flagged `isBase64Encoded` that does not decode to UTF-8 text (a gzip-compressed reply, a binary media type, a Lambda Web Adapter response) is reported unscannable on that leg and follows `on_unscannable` -- blocked by default. Decompress or decode it in a custom `prompt_from=` / `response_from=` if the payload really is text, and pair that with `response_write=` when `apply_masked_data=True`.
- **Masking needs a masking profile.** `apply_masked_data=True` only takes effect when the AI profile is configured to mask-and-allow; a profile that blocks on DLP blocks first.
- **Credentials in environment variables** are demo-grade; use Secrets Manager in production (see [Configure environment](#configure-environment)).

## Resources

- [Prisma AIRS API Reference](https://pan.dev/airs/)
- [Prisma AIRS Documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/)
- [AWS Lambda handler (Python)](https://docs.aws.amazon.com/lambda/latest/dg/python-handler.html)
- [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
