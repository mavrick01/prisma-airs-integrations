# ExecutionInterceptor seam notes — AWS SDK for Java v2

Evidence gathered from the **actual AWS SDK for Java v2 sources, version 2.53.2**, downloaded
from Maven Central (`software.amazon.awssdk:sdk-core:2.53.2:sources`,
`software.amazon.awssdk:bedrockruntime:2.53.2:sources`, `software.amazon.awssdk:json-utils:2.53.2:sources`).
File paths below are paths inside those source jars. Nothing in this document is asserted from memory.

---

## (a) Lifecycle order, and where SigV4 signing happens

`software/amazon/awssdk/core/interceptor/ExecutionInterceptor.java` (interface javadoc) defines the
hook order normatively:

> Methods for a given interceptor are executed in a predictable order [...]
> 1. `beforeExecution` - Read the request before it is modified by other interceptors.
> 2. `modifyRequest` - Modify the request object before it is marshalled into an HTTP request.
> 3. `beforeMarshalling` - Read the request that has potentially been modified by other request interceptors before it is marshalled into an HTTP request.
> 4. `afterMarshalling` - Read the HTTP request after it is created and before it can be modified by other interceptors.
> 5. `modifyHttpRequest` - Modify the HTTP request object before it is transmitted.
> 6. `beforeTransmission` - Read the HTTP request that has potentially been modified by other request interceptors before it is sent to the service.
> 7. `afterTransmission` - Read the HTTP response after it is received and before it can be modified by other interceptors.
> 8. `modifyHttpResponse` - Modify the HTTP response object before it is unmarshalled.
> 9. `beforeUnmarshalling` - Read the HTTP response that has potentially been modified by other request interceptors before it is unmarshalled.
> 10. `afterUnmarshalling` - Read the response after it is created and before it can be modified by other interceptors.
> 11. `modifyResponse` - Modify the response object before before it is returned to the client.
> 12. `afterExecution` - Read the response that has potentially been modified by other request interceptors.

Where the early hooks actually run: **in the client handler, before the HTTP pipeline is even
constructed**. `software/amazon/awssdk/core/internal/handler/BaseClientHandler.java`
(`invokeInterceptorsAndCreateExecutionContext`):

```java
interceptorChain.beforeExecution(interceptorContext, executionAttributes);
interceptorContext = interceptorChain.modifyRequest(interceptorContext, executionAttributes);
```

called from `software/amazon/awssdk/core/internal/handler/BaseSyncClientHandler.java` (`execute`):

```java
return measureApiCallSuccess(executionParams, () -> {
    // Running beforeExecution interceptors and modifyRequest interceptors.
    ExecutionContext executionContext = invokeInterceptorsAndCreateExecutionContext(executionParams);

    HttpResponseHandler<Response<OutputT>> combinedResponseHandler =
        createCombinedResponseHandler(executionParams, executionContext);
    return doExecute(executionParams, executionContext, combinedResponseHandler);
});
```

Signing is a *pipeline stage* deep inside `doExecute`.
`software/amazon/awssdk/core/internal/http/AmazonSyncHttpClient.java` builds the request pipeline:

```java
.first(MakeRequestMutableStage::new)
.then(ApplyTransactionIdStage::new)
.then(MergeCustomHeadersStage::new)
.then(MergeCustomQueryParamsStage::new)
.then(QueryParametersToBodyStage::new)
.then(() -> new CompressRequestStage(httpClientDependencies))
.then(AuthSchemeResolutionStage::new)
.then(EndpointResolutionStage::new)
.then(() -> new HttpChecksumStage(ClientType.SYNC))
.then(ApplyUserAgentStage::new)
.then(MakeRequestImmutableStage::new)
// End of mutating request
.then(RequestPipelineBuilder
          .first(SigningStage::new)
          .then(BeforeTransmissionExecutionInterceptorsStage::new)
          .then(MakeHttpRequestStage::new)
          ...
          .wrappedWith(RetryableStage::new)::build)
```

`software/amazon/awssdk/core/internal/http/pipeline/stages/SigningStage.java` performs the actual
SigV4 signing (both the modern SRA path and the legacy `Signer` path):

```java
// Whether pre / post SRA, if old Signer is setup in context, that's the one to use
if (context.signer() != null) {
    return signRequest(request, context);
}
// else if AUTH_SCHEMES != null (implies SRA), use SelectedAuthScheme
if (context.executionAttributes().getAttribute(SdkInternalExecutionAttribute.AUTH_SCHEMES) != null) {
    ...
    return sraSignRequest(request, context, selectedAuthScheme);
}
```

**Conclusion:** `beforeExecution` runs before marshalling, before auth-scheme and endpoint
resolution, before `SigningStage`, before `MakeHttpRequestStage`, and outside the retry loop.
Aborting there aborts the call before any credential is touched and before any byte leaves the JVM.

---

## (b) Throwing from an early interceptor aborts the call; what reaches the caller

The interface javadoc states the failure contract
(`software/amazon/awssdk/core/interceptor/ExecutionInterceptor.java`):

> An additional `onExecutionFailure` method is provided that is invoked if an execution fails at any
> point during the lifecycle of a request, **including exceptions being thrown from this or other
> interceptors.** [...] The provided exception will be thrown by the service client.

The chain does not guard hook invocation
(`software/amazon/awssdk/core/interceptor/ExecutionInterceptorChain.java`):

```java
public void beforeExecution(Context.BeforeExecution context, ExecutionAttributes executionAttributes) {
    interceptors.forEach(i -> i.beforeExecution(context, executionAttributes));
}
```

The sync handler rethrows unchanged (`BaseSyncClientHandler.java`, `measureApiCallSuccess`):

```java
} catch (Exception e) {
    reportApiCallSuccess(executionParams, false);
    throw e;
}
```

and the SDK's canonical rethrow helper returns `RuntimeException`s as-is
(`software/amazon/awssdk/core/internal/util/ThrowableUtils.java`):

```java
public static RuntimeException failure(Throwable t) {
    if (t instanceof RuntimeException) {
        return (RuntimeException) t;
    }
    ...
    return t instanceof InterruptedException
           ? AbortedException.builder().cause(t).build()
           : SdkClientException.builder().cause(t).build();
}
```

**Conclusion:** an unchecked exception thrown from `beforeExecution` reaches the sync caller
**unchanged** — it is never wrapped, and because it is thrown before `doExecute`, nothing was
marshalled, signed, transmitted, or retried. On the async client, the same exception fails the
returned `CompletableFuture` (`BaseAsyncClientHandler.java`, `measureApiCallSuccess`:
`catch (Exception e) { ...; return CompletableFutureUtils.failedFuture(e); }`).

**Response-side caveat (measured, and it shapes this integration):** hooks that run *inside* the
response handler are wrapped on failure.
`software/amazon/awssdk/core/internal/http/CombinedResponseHandler.java` (`handleSuccessResponse`):

```java
} catch (Exception e) {
    ...
    String errorMessage =
            "Unable to unmarshall response (" + e.getMessage() + "). Response Code: " ...
    throw SdkClientException.builder().message(errorMessage).cause(e).build();
}
```

`RetryableStage.java` catches `SdkExceptionWithRetryAfterHint | SdkException | IOException` and puts
them to the retry policy, and an exception from `modifyResponse` arrives there wrapped in that
`SdkClientException` either way. To deliver a clean, typed exception on the response leg — and to
keep the throw out of the retry loop altogether (no re-send, no double billing) — this integration
records the block during `modifyResponse` and throws from `afterExecution`, whose stage sits
**outside** the retry loop (`AmazonSyncHttpClient.java`):

```java
.then(() -> new UnwrapResponseContainer<>())
.then(() -> new AfterExecutionInterceptorsStage<>())
.wrappedWith(ExecutionFailureExceptionReportingStage::new)
```

`ExecutionFailureExceptionReportingStage.execute` rethrows via `failure(throwable)` (returns
`RuntimeException` unchanged, above), and `AmazonSyncHttpClient.execute` ends with
`catch (RuntimeException e) { throw e; }`. So an exception thrown from `afterExecution` also reaches
the caller unwrapped — with the real, already-received response withheld.

**Async response leg — why `PrismaAirsBlockedException` is an `SdkClientException`.** The async
pipeline wraps the same stage with `AsyncExecutionFailureExceptionReportingStage`
(`AmazonAsyncHttpClient.java`), which does *not* rethrow unchanged; it funnels the failure through
`ThrowableUtils.asSdkException`:

```java
public static SdkException asSdkException(Throwable t) {
    if (t instanceof SdkException) {
        return (SdkException) t;
    }
    return SdkClientException.builder().cause(t).build();
}
```

A plain `RuntimeException` thrown from `afterExecution` would therefore reach an async caller as
`CompletionException -> SdkClientException -> PrismaAirsBlockedException`: a typed `catch` misses,
the leg/category/scan id are buried, and retry wrappers that treat `SdkClientException` as a
transport fault may re-issue a call that policy blocked. `PrismaAirsBlockedException` extends
`SdkClientException` for exactly that reason — `asSdkException` returns it unchanged, so both
clients deliver the same type. Being an `SdkException` does not make it retryable: `retryable()` is
`false`, and both throw sites (`beforeExecution`, `afterExecution`) sit outside `RetryableStage`
regardless.

**What runs the response leg on the async client.** `AsyncResponseHandler.prepare()` registers the
unmarshall-and-interceptor step on the stream future, which `BaosSubscriber.onComplete()` completes
from Netty's `ResponseHandler.channelRead0` — i.e. on the channel's event loop. `modifyResponse`
returns `SdkResponse` synchronously and has no async variant, so the scan HTTP call runs to
completion on that event loop. See the README Limitations for the sizing consequence.

---

## (c) modifyResponse / afterUnmarshalling can REPLACE the response the caller sees

`ExecutionInterceptorChain.java`:

```java
public InterceptorContext modifyResponse(InterceptorContext context, ExecutionAttributes executionAttributes) {
    InterceptorContext result = context;
    for (int i = interceptors.size() - 1; i >= 0; i--) {
        SdkResponse interceptorResult = interceptors.get(i).modifyResponse(result, executionAttributes);

        if (interceptorResult != result.response()) {
            validateInterceptorResult(result.response(), interceptorResult, interceptors.get(i), "modifyResponse");
            result = result.copy(b -> b.response(interceptorResult));
        }
    }
    return result;
}
```

`BaseClientHandler.java` (`runAfterUnmarshallingInterceptors`) — the replaced object **is** what the
caller receives:

```java
context.interceptorChain().afterUnmarshalling(interceptorContext, context.executionAttributes());

interceptorContext = context.interceptorChain().modifyResponse(interceptorContext, context.executionAttributes());

// Store updated context
context.interceptorContext(interceptorContext);

return (OutputT) interceptorContext.response();
```

The only rejected value is `null` (`validateInterceptorResult`:
`Validate.validState(newMessage != null, "Request interceptor '%s' returned null ...")`).
`afterUnmarshalling` is read-only (returns `void`); `modifyResponse` is the replacement seam.

**Structural bonus:** these hooks run **only for successful HTTP responses**.
`CombinedResponseHandler.java` (`handleResponse`):

```java
if (httpResponse.isSuccessful()) {
    OutputT response = handleSuccessResponse(httpResponse, executionAttributes);
    ...
} else {
    return Response.<OutputT>builder().httpResponse(httpResponse)
                                      .exception(handleErrorResponse(httpResponse, executionAttributes))
                                      .isSuccess(false)
                                      .build();
}
```

An AWS error response (throttle, auth failure, validation error) takes the `else` branch and never
touches `afterUnmarshalling`/`modifyResponse` — the genuine AWS exception surfaces untouched with
zero code in this integration.

---

## (d) Registration paths — per-client, and classpath auto-discovery

Both paths are normative in the `ExecutionInterceptor` javadoc:

> 1. *Override Configuration Interceptors* are the most common method for SDK users to register an
>    interceptor. These interceptors are explicitly added to the client builder's override
>    configuration when a client is created using the
>    `ClientOverrideConfiguration.Builder#addExecutionInterceptor(ExecutionInterceptor)` method.
> 2. *Global Interceptors* are interceptors loaded from the classpath **for all clients**. When any
>    service client is created by a client builder, all jars on the classpath (from the perspective
>    of the current thread's classloader) are checked for a file named
>    `'/software/amazon/awssdk/global/handlers/execution.interceptors'`. Any interceptors listed in
>    these files (new line separated) are instantiated using their default constructor and loaded
>    into the client.

The loader exists and does exactly that
(`software/amazon/awssdk/core/interceptor/ClasspathInterceptorChainFactory.java`):

```java
private static final String GLOBAL_INTERCEPTOR_PATH = "software/amazon/awssdk/global/handlers/execution.interceptors";
...
return new ArrayList<>(createExecutionInterceptorsFromClasspath(GLOBAL_INTERCEPTOR_PATH));
...
return createExecutionInterceptorsFromResources(classLoader().getResources(path))
...
Object executionInterceptorObject = executionInterceptorClass.newInstance();
```

**Implication:** a one-line resource file in any jar on the classpath registers the interceptor on
**every AWS SDK client in the JVM** — every service, every framework, every future code path. Nobody
has to remember anything at any call site or client-construction site. This is why
`PrismaAirsInterceptor` keeps a public no-arg constructor with fully env-driven defaults.

---

## Also verified from the same sources

- The two streaming operations exist **only on the async client**: `converseStream` and
  `invokeModelWithResponseStream` are declared on `BedrockRuntimeAsyncClient` and absent from the
  sync `BedrockRuntimeClient` interface (bedrockruntime 2.53.2 sources).
- `software.amazon.awssdk.protocols.jsoncore.JsonNode` / `JsonWriter` ship in
  `software.amazon.awssdk:json-utils`, a compile-scope transitive of `bedrockruntime`
  (bedrockruntime POM → `aws-json-protocol` → `json-utils`; `json-utils` is also declared directly
  in the `services` parent POM). Zero third-party JSON libraries are needed.
- The `services` parent POM gives every service module `apache5-client` and `netty-nio-client` at
  runtime scope, so `bedrockruntime` alone is a complete dependency set for a working sync client.
- Model API surface used by the interceptor, verified in bedrockruntime 2.53.2 sources:
  `ConverseRequest.messages()/modelId()`, `ConverseStreamRequest.messages()/modelId()`,
  `InvokeModelRequest.body()` (`SdkBytes`) / `modelId()`, `InvokeModelResponse.body()` (`SdkBytes`,
  fully buffered), `ContentBlock.text()/fromText()`, `ConversationRole.USER`,
  `ConverseOutput.builder().message(...)`, and `StopReason.CONTENT_FILTERED`.
