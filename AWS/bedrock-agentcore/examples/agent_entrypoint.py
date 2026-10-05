"""
Example: an AgentCore agent whose loop is guarded at all four legs.

This is a hand-rolled Bedrock Converse tool loop -- the shape AgentCore hosts --
with the Prisma AIRS guard placed at each leg:

    before-model   guard.scan_prompt(user_text)
    after-model    guard.scan_response(reply, prompt=user_text)
    before-tool    guard.scan_tool_input(name, args)   (via the @guard.guard_tool wrapper)
    after-tool     guard.scan_tool_output(...)         (same wrapper)

The guard pulls the AgentCore request id and session id from the runtime context
automatically, so each scan in Strata Cloud Manager lines up with this invocation
in the AgentCore logs. A block raises PrismaAirsBlocked, which the entrypoint
turns into a safe refusal instead of letting the loop continue.

Deploy: this file plus prisma_airs_agentcore.py. Requires boto3 (for Bedrock)
and bedrock-agentcore (the runtime); the guard itself needs neither.
"""

import os

import boto3
from bedrock_agentcore.runtime import BedrockAgentCoreApp

from prisma_airs_agentcore import PrismaAirsGuard, PrismaAirsBlocked

app = BedrockAgentCoreApp()
bedrock = boto3.client("bedrock-runtime")
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")

guard = PrismaAirsGuard(
    app_name="support-agent",
    ai_model=MODEL_ID,
    # agent_arn is optional: on AgentCore the guard derives it from the runtime's
    # OTEL resource attributes automatically. Pass one here only to override, e.g.
    # off-runtime, or set AGENT_ARN in your deployment config.
    agent_arn=os.environ.get("AGENT_ARN"),
)


# A tool whose input and output are both scanned automatically. The after-tool
# leg is where a poisoned tool result (prompt injection returned by an external
# system, or a leaked credential) is caught before it re-enters the model.
@guard.guard_tool(server_name="crm")
def lookup_ticket(ticket_id: str) -> dict:
    # A real implementation would call your ticketing system here.
    return {"ticket_id": ticket_id, "status": "open", "summary": "Customer asks about refunds."}


TOOLS = {"lookup_ticket": lookup_ticket}
TOOL_SPEC = {
    "tools": [{
        "toolSpec": {
            "name": "lookup_ticket",
            "description": "Look up a support ticket by id.",
            "inputSchema": {"json": {"type": "object",
                                     "properties": {"ticket_id": {"type": "string"}},
                                     "required": ["ticket_id"]}},
        }
    }]
}


@app.entrypoint
def handler(payload):
    user_text = (payload or {}).get("prompt", "")

    try:
        # ---- before-model -------------------------------------------------
        guard.scan_prompt(user_text)

        messages = [{"role": "user", "content": [{"text": user_text}]}]
        for _ in range(4):  # bounded tool loop
            reply = bedrock.converse(modelId=MODEL_ID, messages=messages, toolConfig=TOOL_SPEC)
            out = reply["output"]["message"]
            messages.append(out)

            tool_uses = [b["toolUse"] for b in out.get("content", []) if "toolUse" in b]
            if not tool_uses:
                text = "".join(b.get("text", "") for b in out.get("content", []))
                # ---- after-model ------------------------------------------
                # A turn that assembles to no text is unscannable, so it follows
                # on_unscannable (block by default) and lands in the handler
                # below as a safe refusal rather than being returned unscanned.
                guard.scan_response(text, prompt=user_text)
                return {"reply": text}

            tool_results = []
            for use in tool_uses:
                fn = TOOLS.get(use["name"])
                # @guard.guard_tool scans this call's input and output
                result = fn(**use["input"]) if fn else {"error": "unknown tool"}
                tool_results.append({"toolResult": {
                    "toolUseId": use["toolUseId"],
                    "content": [{"json": result}],
                }})
            messages.append({"role": "user", "content": tool_results})

        return {"reply": "Sorry, I could not complete that request."}

    except PrismaAirsBlocked as blocked:
        # A safe refusal -- the loop stops, nothing further is sent to the model.
        return {"reply": "That request was blocked by security policy.",
                "blocked": {"leg": blocked.leg,
                            "category": blocked.verdict.get("category"),
                            "scan_id": blocked.verdict.get("scan_id")}}


if __name__ == "__main__":
    app.run()
