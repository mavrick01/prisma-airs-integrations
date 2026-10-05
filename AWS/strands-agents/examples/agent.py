"""
Example: a Strands agent protected at all four legs by one hook provider.

The agent is ordinary Strands code. Adding security is one constructor argument:
`hooks=[PrismaAIRSHooks(...)]`. From then on every model call and every tool
call the agent loop makes is scanned -- the prompt and response by the
model-call events, and each tool's input and output as first-class tool_events
by the tool-call events. (`Agent.structured_output()` runs outside that loop and
is not covered; see the Limitations section of the README.)

Enforcement follows what each Strands event permits (a framework capability
boundary, not a choice):
  * a blocked prompt is cancelled (the model is not called);
  * a blocked tool input is cancelled;
  * a poisoned or leaking tool OUTPUT is replaced with a safe error result;
  * a blocked model RESPONSE can only be retried, then fails closed -- Strands
    does not permit substituting a model response.
"""

import os

from strands import Agent, tool
from strands.models.bedrock import BedrockModel

from prisma_airs_strands import PrismaAIRSHooks, PrismaAirsResponseBlocked

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")


@tool
def lookup_ticket(ticket_id: str) -> str:
    """Look up a support ticket by id."""
    # A real implementation calls your ticketing system; whatever it returns
    # is scanned as a tool_event output before it re-enters the model.
    return "Ticket %s: customer asks about the refund policy." % ticket_id


agent = Agent(
    model=BedrockModel(model_id=MODEL_ID),
    tools=[lookup_ticket],
    hooks=[PrismaAIRSHooks(app_name="support-agent", ai_model=MODEL_ID)],
)


if __name__ == "__main__":
    try:
        print(agent("Please look up ticket T-1001 and summarize it."))
    except PrismaAirsResponseBlocked as blocked:
        # Reached only if the model kept producing blocked content past the
        # retry limit. The blocked message was never added to history.
        print("The response was withheld by security policy (category=%s)."
              % blocked.verdict.get("category"))
