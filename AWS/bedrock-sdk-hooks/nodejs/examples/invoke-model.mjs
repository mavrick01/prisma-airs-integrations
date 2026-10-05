/**
 * Example: the same protection on the legacy InvokeModel API.
 *
 * InvokeModel bodies are model-family dialects rather than one schema; the
 * hook extracts the prompt for the common families (messages-style chat
 * bodies, Amazon Nova/Titan, Meta, Mistral, Cohere) and falls back to
 * scanning the entire serialized body for anything it does not recognize --
 * unknown models err toward inspecting too much rather than too little.
 *
 * onBlock: "respond" shows the second blocking style: instead of throwing,
 * the caller receives a well-formed response whose text says the call was
 * blocked, with the verdict attached under $prismaAirs -- useful when the
 * calling code cannot be taught a new exception.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";

import { protectClient } from "../prisma-airs-hook.mjs";

const MODEL_ID = process.env.BEDROCK_MODEL_ID || "us.amazon.nova-lite-v1:0";

const bedrock = protectClient(new BedrockRuntimeClient({}), {
  appName: "invoke-example",
  onBlock: "respond",
});

const result = await bedrock.send(new InvokeModelCommand({
  modelId: MODEL_ID,
  contentType: "application/json",
  body: JSON.stringify({
    messages: [{ role: "user", content: [{ text: "One sentence: what is S3?" }] }],
  }),
}));

console.log(JSON.parse(new TextDecoder().decode(result.body)));
console.log(result.$prismaAirs ?? "not blocked");
