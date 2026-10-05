"""
Example: an API Gateway chatbot handler on Amazon Bedrock, protected by @airs_protect.

The handler is ordinary application code -- it does not know AIRS exists. The
decorator scans the prompt before this function runs and the response before
API Gateway sees it. The default extractors already understand this event and
result shape: the prompt rides in the JSON body's "prompt" field and the reply
goes back in a "response" field, which are the first keys each extractor tries.

Deploy package layout (no dependencies beyond boto3, which Lambda provides):

    handler_bedrock_apigw.py
    prisma_airs_decorator.py
"""

import base64
import json
import os

import boto3

from prisma_airs_decorator import airs_protect

bedrock = boto3.client("bedrock-runtime")
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")


@airs_protect(
    app_name="support-chat",
    ai_model=MODEL_ID,
    # end-user identity for SCM attribution, e.g. from an HTTP API JWT authorizer
    app_user_from=lambda event, context: (((event.get("requestContext") or {})
                                           .get("authorizer") or {})
                                          .get("jwt") or {}).get("claims", {}).get("email"),
)
def handler(event, context):
    raw = event["body"]
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    body = json.loads(raw)
    reply = bedrock.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": body["prompt"]}]}],
    )
    text = reply["output"]["message"]["content"][0]["text"]
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"response": text}),
    }
