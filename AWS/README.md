# AWS Integrations for Prisma AIRS

This directory contains integrations between AWS AI services and Palo Alto Networks Prisma AI Runtime Security (AIRS).

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

## Overview

| Integration | Method | Use Case |
|-------------|--------|----------|
| [lambda-decorator](./lambda-decorator/) | Python decorator on the Lambda handler | Prompt/response scanning for **any** Lambda-hosted AI app, regardless of model provider or framework |
| [bedrock-sdk-hooks](./bedrock-sdk-hooks/) | SDK-native interceptors on the Bedrock client (Python · Node.js · Java · Go) | Scans **every** Bedrock model call an application makes, in any of the four first-party SDKs, without changing application code paths |
| [bedrock-agentcore](./bedrock-agentcore/) | A guard called at the four legs of an AgentCore agent loop | Full four-leg coverage including tool-call input/output for agents on Amazon Bedrock AgentCore Runtime |
| [strands-agents](./strands-agents/) | Typed `HookProvider` for the Strands Agents SDK | Four-leg coverage via the framework's own hook lifecycle; enforcement shaped by each event's capability boundary |

*Further AWS integrations (ai-gateway) are in progress and land with their own PRs.*

## Choosing an Integration

The integrations stand at different seats in the stack, and **what each can scan is what physically passes its seat**:

- **Function boundary** ([lambda-decorator](./lambda-decorator/)) — widest reach, least depth. Works with any language-agnostic event shape and any model, but sees only the prompt entering and the response leaving the function. Agent activity inside the handler is invisible.
- **SDK client** ([bedrock-sdk-hooks](./bedrock-sdk-hooks/)) — sees every model call, including ones your framework makes on your behalf. A Bedrock guardrail is a request parameter someone can forget; an interceptor registered on the client applies to every call through it — in Python, Node.js, Java, and Go.
- **Agent loop** ([bedrock-agentcore](./bedrock-agentcore/), [strands-agents](./strands-agents/)) — the only seats that see tool use. Deepest coverage, narrowest fit: they require that specific runtime or framework.

They compose: a decorated Lambda whose handler uses a hooked Bedrock client gets boundary scanning *and* per-call scanning from two independent seats. The intended pairing for agents is a gateway for model traffic plus an in-loop seat for the tool legs the gateway cannot see.

## Security Features

These integrations provide protection against:

- Prompt injection attacks
- Sensitive data exposure (PII, credentials, secrets)
- Malicious URL detection
- Toxic or harmful content
- Malicious code patterns
- AI manipulation attempts

## Getting Started

1. Choose the integration whose seat matches your architecture (see above)
2. Follow the setup instructions in the respective directory
3. Obtain API credentials from [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)

## Resources

- [Prisma AIRS Documentation](https://pan.dev/airs/)
- [Prisma AIRS Admin Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
- [Amazon Bedrock](https://docs.aws.amazon.com/bedrock/)
- [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/)
- [Strands Agents SDK](https://strandsagents.com)