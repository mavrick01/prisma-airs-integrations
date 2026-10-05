# Seam notes: where the hook sits in the AWS SDK for JavaScript v3

Research notes for `prisma-airs-hook.mjs`. All excerpts below are quoted from the
installed source of `@aws-sdk/client-bedrock-runtime@3.1113.0` and its bundled
`@smithy/core` (the middleware machinery formerly published as
`@smithy/middleware-stack`, `@smithy/middleware-serde`, and
`@smithy/middleware-http-signing` now ships as `@smithy/core` submodules).
Paths are relative to `node_modules/`.

## (a) Step order, and where SigV4 signing runs

The middleware stack sorts absolute entries by step weight, then priority weight
(descending). From `@smithy/core/dist-es/submodules/client/middleware-stack/MiddlewareStack.js`:

```js
const sort = (entries) => entries.sort((a, b) => stepWeights[b.step] - stepWeights[a.step] ||
    priorityWeights[b.priority || "normal"] - priorityWeights[a.priority || "normal"]);
...
const stepWeights = {
    initialize: 5,
    serialize: 4,
    build: 3,
    finalizeRequest: 2,
    deserialize: 1,
};
const priorityWeights = {
    high: 3,
    normal: 2,
    low: 1,
};
```

So the step order is `initialize -> serialize -> build -> finalizeRequest -> deserialize`,
and within a step `high -> normal -> low`.

SigV4 signing is `httpSigningMiddleware`, registered at step **`finalizeRequest`**,
relative-**after** `retryMiddleware` (which itself is `finalizeRequest` / priority
`high`). From `@smithy/core/dist-es/legacy-root-exports/middleware-http-signing/getHttpSigningMiddleware.js`:

```js
export const httpSigningMiddlewareOptions = {
    step: "finalizeRequest",
    tags: ["HTTP_SIGNING"],
    name: "httpSigningMiddleware",
    aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
    override: true,
    relation: "after",
    toMiddleware: "retryMiddleware",
};
```

and from `.../middleware-http-signing/httpSigningMiddleware.js`, the actual
signature happens inside that middleware's handler ("after retryMiddleware"
means inside the retry loop, so every attempt is re-signed):

```js
const output = await next({
    ...args,
    request: await signer.sign(args.request, identity, signingProperties),
}).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
```

`retryMiddleware`, for reference
(`@smithy/core/dist-es/submodules/retry/middleware-retry/retryMiddleware.js`):

```js
export const retryMiddlewareOptions = {
    name: "retryMiddleware",
    tags: ["RETRY"],
    step: "finalizeRequest",
    priority: "high",
    override: true,
};
```

The full resolved order for a real `ConverseCommand`, printed by
`client.middlewareStack.identifyOnResolve(true)` at send time:

```
[
  'loggerMiddleware - initialize',
  'httpAuthSchemeMiddleware - serialize',
  'endpointV2Middleware - serialize',
  'serializerMiddleware - serialize',
  'contentLengthMiddleware - build',
  'getUserAgentMiddleware - build',
  'hostHeaderMiddleware - build',
  'recursionDetectionMiddleware - build',
  'retryMiddleware - finalizeRequest',
  'httpSigningMiddleware (a.k.a. apiKeyMiddleware,tokenMiddleware,awsAuthMiddleware) - finalizeRequest',
  'deserializerMiddleware - deserialize'
]
```

## (b) A throwing early middleware aborts before signing and before any network I/O

`stack.resolve` builds one nested handler chain: the sorted list is reversed and
each middleware wraps the next, so the *earliest*-sorted middleware is the
*outermost* function, and the innermost handler is the HTTP request handler
itself. From `MiddlewareStack.js`:

```js
resolve: (handler, context) => {
    for (const middleware of getMiddlewareList()
        .map((entry) => entry.middleware)
        .reverse()) {
        handler = middleware(handler, context);
    }
    ...
    return handler;
},
```

and from `@smithy/core/dist-es/submodules/client/smithy-client/command.js`, the
innermost handler is the network call:

```js
return stack.resolve((request) => requestHandler.handle(request.request, requestOptions), handlerExecutionContext);
```

Because the chain is plain function nesting, an early middleware that throws
(or that returns without calling `next(args)`) means **no inner middleware ever
runs**: no serialization, no signing (`finalizeRequest`), and no
`requestHandler.handle` (no socket is opened). Verified empirically with a
middleware at `serialize`/`high` that throws, on a client whose
`requestHandler.handle` sets a flag:

```
HOOK SEES INPUT: {"modelId":"us.amazon.nova-lite-v1:0","op":"ConverseCommand"}
ABORT OUTCOME: BLOCKED-BY-TEST | requestHandler invoked: false
```

The same client with valid middleware and deliberately invalid static
credentials reaches AWS and fails with `UnrecognizedClientException` -- which is
what makes "blocked by the hook" and "reached AWS" cleanly distinguishable
outcomes in `scripts/validate.mjs`.

## (c) Reading and replacing the deserialized output

The deserializer is the *innermost* middleware (step `deserialize`, weight 1).
It calls `next` (the HTTP handler), parses the raw response, and returns
`{ response, output }` up the chain. From
`@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js`:

```js
export const schemaDeserializationMiddleware = (config) => (next, context) => async (args) => {
    const { response } = await next(args);
    const { operationSchema } = getSmithyContext(context);
    ...
    const parsed = await config.protocol.deserializeResponse(...);
    return {
        response,
        output: parsed,
    };
```

Any middleware *outer* to it therefore receives the fully deserialized
operation output as `result.output` from its own `await next(args)`, and may
mutate or replace it before returning. The caller's promise resolves with
whatever `output` the outermost middleware returns -- from
`@smithy/core/dist-es/submodules/client/smithy-client/client.js`:

```js
return handler(command).then((result) => result.output);
```

On an AWS error (HTTP >= 300) the deserializer does not return -- it throws the
modeled service exception, so the `await next(args)` in an outer middleware
rejects and the genuine AWS error propagates untouched. From
`@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js`:

```js
if (response.statusCode >= 300) {
    const bytes = await collectBody(response.body, context);
    if (bytes.byteLength > 0) {
        Object.assign(dataObject, await deserializer.read(15, bytes));
    }
    await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
    throw new Error("@smithy/core/protocols - HTTP Protocol error handler failed to throw.");
}
```

**InvokeModel output body type.** The `body` member is an `httpPayload` blob;
the payload bytes are collected into a `Uint8ArrayBlobAdapter`, a `Uint8Array`
subclass (so reading it is non-destructive, unlike the Python SDK's
`StreamingBody`). From `@smithy/core/dist-es/submodules/protocols/collect-stream-body.js`:

```js
export const collectBody = async (streamBody = new Uint8Array(), context) => {
    if (streamBody instanceof Uint8Array) {
        return Uint8ArrayBlobAdapter.mutate(streamBody);
    }
    ...
```

and `@smithy/core/dist-es/submodules/serde/util-stream/blob/Uint8ArrayBlobAdapter.js`:

```js
return class Uint8ArrayBlobAdapter extends Uint8Array {
    ...
    static mutate(source) {
        Object.setPrototypeOf(source, Uint8ArrayBlobAdapter.prototype);
        return source;
    }
    transformToString(encoding = "utf-8") { ... }
```

(`@aws-sdk/client-bedrock-runtime/dist-types/commands/InvokeModelCommand.d.ts`
confirms: `body: Uint8ArrayBlobAdapter`.) On the response leg the hook replaces
a body that already exists, so it re-attaches that body's prototype to the new
bytes and `transformToString()` keeps working. On the prompt leg there is no
original to borrow from -- the block short-circuits the chain before the
deserializer ever runs -- so the fabricated bytes carry their own
`transformToString()` / `transformToByteArray()` instead of the adapter
prototype: the reader methods behave the same, though `instanceof
Uint8ArrayBlobAdapter` is false, which importing the adapter (a `@smithy`
dependency this file does not take) is the only way to change.

## (d) Registering per-client so ALL commands are covered

`client.middlewareStack.add(middleware, options)` is the public API. `options`
takes `step`, `priority`, `name`, `tags`, `override` (and relative variants via
`addRelativeTo`). Defaults from `MiddlewareStack.js`:

```js
add: (middleware, options = {}) => {
    const { name, override, aliases: _aliases } = options;
    const entry = {
        step: "initialize",
        priority: "normal",
        middleware,
        ...options,
    };
```

Every `client.send(command)` resolves the **client** stack concatenated with the
command's own stack, so a middleware added on the client covers every command
sent through that client. From `client.js`:

```js
handler = command.resolveMiddleware(this.middlewareStack, this.config, options);
```

and from `command.js`:

```js
const stack = clientStack.concat(this.middlewareStack);
...
return stack.resolve((request) => requestHandler.handle(request.request, requestOptions), handlerExecutionContext);
```

The execution context passed to each middleware carries `commandName`
(e.g. `"ConverseCommand"`) and `clientName`, which is how the hook scopes itself
to the four model-invocation operations and passes everything else through.

## The resolved-handler cache

`Client.send` can cache the fully-resolved middleware handler per command
constructor, keyed in a `WeakMap`, when the client was constructed with
`cacheMiddleware: true` and `send` is called without per-call options. From
`@smithy/core/dist-es/submodules/client/smithy-client/client.js`:

```js
const useHandlerCache = options === undefined && this.config.cacheMiddleware === true;
let handler;
if (useHandlerCache) {
    if (!this.handlers) {
        this.handlers = new WeakMap();
    }
    const handlers = this.handlers;
    if (handlers.has(command.constructor)) {
        handler = handlers.get(command.constructor);
    }
    else {
        handler = command.resolveMiddleware(this.middlewareStack, this.config, options);
        handlers.set(command.constructor, handler);
    }
}
```

A handler resolved BEFORE `protectClient` was called would therefore keep
bypassing a middleware added later, for every subsequent send of that command
type. `cacheMiddleware` is not enabled by default for bedrock-runtime, but the
hook defends against the enable-cache-then-late-protect ordering anyway:
`protectClient` resets `client.handlers` after adding the middleware, so the
next send re-resolves through the scan. (`destroy()` shows `delete
this.handlers` is the SDK's own way of dropping the cache.)

## Chosen seat

One middleware, registered once per client:

```js
client.middlewareStack.add(scanMiddleware, {
  step: "initialize", priority: "high", name: "prismaAirsScanMiddleware",
  tags: ["PRISMA_AIRS"], override: true,
});
```

`initialize`/`high` makes it the outermost middleware: on the way in it sees the
unserialized command input (`args.input` -- `modelId`, `messages`, `body`) and a
throw or early return aborts the call before serialization, signing, and any
network I/O; on the way out its `await next(args)` resolves only after
deserialization (and after the retry loop has fully settled), so it can scan and
replace the parsed output before the caller's promise resolves.
