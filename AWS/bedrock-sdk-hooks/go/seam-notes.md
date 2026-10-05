# Seam notes: where the Prisma AIRS middleware sits in aws-sdk-go-v2

Working notes from reading the actual SDK source, not documentation. Everything
below is quoted from the modules the hook builds against, fetched through the
Go module proxy into the local module cache:

| Module | Version examined |
|--------|------------------|
| `github.com/aws/smithy-go` | v1.27.8 |
| `github.com/aws/aws-sdk-go-v2` (core) | v1.43.6 |
| `github.com/aws/aws-sdk-go-v2/service/bedrockruntime` | v1.57.3 |
| `github.com/aws/aws-sdk-go-v2/config` | v1.32.37 |

File paths below are relative to each module root (as extracted under
`$GOMODCACHE/github.com/aws/...@<version>/`).

## (a) Step order, and where SigV4 signing runs

Every aws-sdk-go-v2 operation is executed through a smithy middleware stack of
five steps. `smithy-go@v1.27.8/middleware/stack.go` (lines 9–24):

```go
// Stack provides protocol and transport agnostic set of middleware split into
// distinct steps. Steps have specific transitions between them, that are
// managed by the individual step.
//
// Steps are composed as middleware around the underlying handler in the
// following order:
//
//   Initialize -> Serialize -> Build -> Finalize -> Deserialize -> Handler
//
// Any middleware within the chain may choose to stop and return an error or
// response. Since the middleware decorate the handler like a call stack, each
// middleware will receive the result of the next middleware in the chain.
```

The composition is literal decoration — Initialize is outermost, the transport
handler innermost (`stack.go`, lines 98–110):

```go
func (s *Stack) HandleMiddleware(ctx context.Context, input interface{}, next Handler) (
	output interface{}, metadata Metadata, err error,
) {
	h := DecorateHandler(next,
		s.Initialize,
		s.Serialize,
		s.Build,
		s.Finalize,
		s.Deserialize,
	)

	return h.Handle(ctx, input)
}
```

The `next` handler decorated last is the HTTP client itself — network I/O
happens only inside the terminal handler, after every step
(`smithy-go@v1.27.8/transport/http/client.go`, lines 58–63):

```go
// Handle implements the middleware Handler interface, that will invoke the
// underlying HTTP client. Requires the input to be a Smithy *Request. Returns
// a smithy *Response, or error if the request failed.
func (c ClientHandler) Handle(ctx context.Context, input interface{}) (
	out interface{}, metadata middleware.Metadata, err error,
) {
```

**SigV4 signing is a Finalize-step middleware with ID `"Signing"`.** In current
SDK versions each service package carries it in `auth.go`
(`bedrockruntime@v1.57.3/auth.go`, lines 312–322):

```go
type signRequestMiddleware struct {
	options Options
}

func (*signRequestMiddleware) ID() string {
	return "Signing"
}

func (m *signRequestMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
	out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
) {
```

registered on the Finalize step together with the rest of the auth chain
(`bedrockruntime@v1.57.3/api_client.go`, lines 522–533):

```go
	if err := stack.Finalize.Add(&resolveAuthSchemeMiddleware{operation: operation, options: options}, middleware.Before); err != nil {
		return err
	}
	if err := stack.Finalize.Insert(&getIdentityMiddleware{options: options}, "ResolveAuthScheme", middleware.After); err != nil {
		return err
	}
	if err := stack.Finalize.Insert(&resolveEndpointV2Middleware{options: options}, "GetIdentity", middleware.After); err != nil {
		return err
	}
	if err := stack.Finalize.Insert(&signRequestMiddleware{options: options}, "ResolveEndpointV2", middleware.After); err != nil {
		return err
	}
```

(The generic `SignHTTPRequestMiddleware` in the core module is the same story:
`aws-sdk-go-v2@v1.43.6/aws/signer/v4/middleware.go` line 255 declares it
"a `FinalizeMiddleware` implementation for SigV4" and line 290 implements
`HandleFinalize`.)

The retry loop is also a Finalize middleware, inserted **before** `"Signing"`
so every retry attempt is re-signed inside it
(`aws-sdk-go-v2@v1.43.6/aws/retry/middleware.go`, lines 82 and 469–471):

```go
func (r *Attempt) ID() string { return "Retry" }
...
	// index retry to before signing, if signing exists
	if err := stack.Finalize.Insert(attempt, "Signing", smithymiddle.Before); err != nil {
```

Consequence: **anything registered at Initialize runs before serialization,
before the retry loop, before signing, and before any network I/O** — and its
post-`next` code runs after all of those have fully unwound (i.e. once per
operation, not once per retry attempt).

## (b) Aborting at Initialize: nothing downstream runs, and how the error surfaces

At the Initialize step the middleware receives the operation's **typed input**
(`smithy-go@v1.27.8/middleware/step_initialize.go`, lines 13–20):

```go
type InitializeInput struct {
	Parameters interface{}
}

// InitializeOutput provides the result returned by the next InitializeHandler.
type InitializeOutput struct {
	Result interface{}
}
```

`Parameters` is exactly what the caller passed —
`bedrockruntime@v1.57.3/api_client.go` line 320 hands the operation input
straight into the decorated stack:

```go
	decorated := middleware.DecorateHandler(handler, stack)
	result, metadata, err = decorated.Handle(ctx, params)
```

Because the steps "decorate the handler like a call stack" (stack.go quote in
(a)), a middleware that **returns an error without calling `next`** ends the
call right there: Serialize, Build, Finalize (signing), Deserialize, and the
HTTP handler are all reached only through `next`, and none of them run. The
same holds for returning a fabricated `InitializeOutput` — the stack simply
propagates whatever the outermost middleware returns.

What the caller receives: `invokeOperation` wraps any error coming out of the
stack in `*smithy.OperationError` (`bedrockruntime@v1.57.3/api_client.go`,
lines 320–337):

```go
	result, metadata, err = decorated.Handle(ctx, params)
	if err != nil {
		...
		err = &smithy.OperationError{
			ServiceID:     ServiceID,
			OperationName: opID,
			Err:           err,
		}
	}
```

and `OperationError` implements `Unwrap` (`smithy-go@v1.27.8/errors.go`,
lines 44–61):

```go
type OperationError struct {
	ServiceID     string
	OperationName string
	Err           error
}
...
// Unwrap returns the nested error if any, or nil.
func (e *OperationError) Unwrap() error { return e.Err }

func (e *OperationError) Error() string {
	return fmt.Sprintf("operation error %s: %s, %v", e.ServiceID, e.OperationName, e.Err)
}
```

So a custom error returned by our Initialize middleware reaches the caller as
`operation error Bedrock Runtime: Converse, <our message>` and
**`errors.As(err, &blockedErr)` recovers the typed `*BlockedError`** through
the `Unwrap` chain. This is exactly the boto3 sibling's "raised before signed,
sent, or billed" semantics.

## (c) Reading and replacing the deserialized operation output

The step that parses the HTTP response is the service's own
`OperationDeserializer`, a Deserialize-step middleware
(`bedrockruntime@v1.57.3/deserializers.go`, lines 235–266):

```go
type awsRestjson1_deserializeOpConverse struct {
}

func (*awsRestjson1_deserializeOpConverse) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpConverse) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	...
	output := &ConverseOutput{}
	out.Result = output
```

with (`smithy-go@v1.27.8/middleware/step_deserialize.go`, lines 16–20):

```go
// DeserializeOutput provides the result returned by the next DeserializeHandler.
type DeserializeOutput struct {
	RawResponse interface{}
	Result      interface{}
}
```

A Deserialize middleware inserted before `"OperationDeserializer"`
(`stack.Deserialize.Insert(m, "OperationDeserializer", middleware.Before)`)
therefore sees `out.Result` already populated with the typed output when its
`next` call returns, and may replace it. But note it sits **inside the retry
loop** (Retry is Finalize, Deserialize is inner to Finalize), so it runs once
per attempt.

**The same replaced/inspected `Result` is equally visible at the Initialize
step, after the whole stack has unwound** — each step's wrap handler forwards
the result value upward unchanged. `step_finalize.go` lines 268–275 (the
Serialize and Build wrappers are structurally identical):

```go
func (w finalizeWrapHandler) HandleFinalize(ctx context.Context, in FinalizeInput) (
	out FinalizeOutput, metadata Metadata, err error,
) {
	res, metadata, err := w.Next.Handle(ctx, in.Request)
	return FinalizeOutput{
		Result: res,
	}, metadata, err
}
```

and `step_initialize.go` lines 269–276:

```go
func (w initializeWrapHandler) HandleInitialize(ctx context.Context, in InitializeInput) (
	out InitializeOutput, metadata Metadata, err error,
) {
	res, metadata, err := w.Next.Handle(ctx, in.Parameters)
	return InitializeOutput{
		Result: res,
	}, metadata, err
}
```

So this hook implements **both legs in one Initialize middleware**: the code
before `next` scans the typed input (prompt leg, pre-serialization, pre-sign),
and the code after `next` receives the fully deserialized typed output —
outside the retry loop, so a response is scanned exactly once — and may
mutate or replace `out.Result` before the operation function returns it.

Replacement must preserve the concrete type, because the operation function
performs an unchecked type assertion
(`bedrockruntime@v1.57.3/api_op_Converse.go`, lines 61–68):

```go
	result, metadata, err := c.invokeOperation(ctx, "Converse", params, optFns, c.addOperationConverseMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ConverseOutput)
	out.ResultMetadata = metadata
	return out, nil
```

Substitution feasibility per operation, from the output types:

* **`Converse`** — feasible. `ConverseOutput` (api_op_Converse.go lines
  175–196) is a plain exported struct: `Output types.ConverseOutput`
  (satisfiable with `&types.ConverseOutputMemberMessage{Value: types.Message{...}}`,
  types/types.go lines 769–773), `StopReason types.StopReason`
  (`types.StopReasonContentFiltered = "content_filtered"`, types/enums.go
  line 981), `Usage *types.TokenUsage`, `Metrics *types.ConverseMetrics`.
* **`InvokeModel`** — feasible. `InvokeModelOutput` (api_op_InvokeModel.go
  lines 131–146) carries `Body []byte` and `ContentType *string`; a block
  simply replaces the body bytes.
* **`ConverseStream` / `InvokeModelWithResponseStream`** — **not feasible.**
  The stream lives in an unexported field only the deserializer can set
  (api_op_ConverseStream.go lines 186–198):

  ```go
  type ConverseStreamOutput struct {
  	eventStream *ConverseStreamEventStream
  	...
  }

  // GetStream returns the type to interact with the event stream.
  func (o *ConverseStreamOutput) GetStream() *ConverseStreamEventStream {
  	return o.eventStream
  }
  ```

  A fabricated output would return a nil stream and the caller's read loop
  would panic. **For the two streaming operations the hook is honest about
  this: a block always surfaces as `*BlockedError`, even in respond mode**
  (documented in the README).

Block metadata travels on `middleware.Metadata`
(`smithy-go@v1.27.8/middleware/metadata.go`, lines 16–18, 24, 49: a
`map[interface{}]interface{}` with `Get`/`Set`), which `invokeOperation`
returns and the operation function stores on `out.ResultMetadata` (assertion
quote above) — that is where the hook attaches its `BlockInfo` in respond
mode.

## (d) Registration: per client and per config

`Options.APIOptions` is the SDK's public mutation seam
(`bedrockruntime@v1.57.3/options.go`, lines 24–28):

```go
type Options struct {
	// Set of options to modify how an operation is invoked. These apply to all
	// operations invoked for this client. Use functional options on operation call to
	// modify this list for per operation behavior.
	APIOptions []func(*middleware.Stack) error
```

Every operation invocation builds a fresh stack, adds the SDK's own
middleware, then applies the client's `APIOptions` mutators
(`bedrockruntime@v1.57.3/api_client.go`, lines 290–294 inside
`invokeOperation` — this runs after `addCommonMiddlewares` and the
operation-specific registrations, so the standard middleware is already in
place when ours is added):

```go
	for _, fn := range options.APIOptions {
		if err := fn(stack); err != nil {
			return nil, metadata, err
		}
	}
```

**Per client:** a functional option appends to `o.APIOptions` at construction
— `bedrockruntime.NewFromConfig(awsCfg, prismaairs.WithProtection(cfg))`.

**Per config:** `NewFromConfig` copies `cfg.APIOptions` into the client's
options (`api_client.go`, lines 625–633):

```go
func NewFromConfig(cfg aws.Config, optFns ...func(*Options)) *Client {
	opts := Options{
		Region:                     cfg.Region,
		...
		APIOptions:                 cfg.APIOptions,
```

and `config.WithAPIOptions` plants mutators on the shared `aws.Config`
(`config@v1.32.37/load_options.go`, lines 850–862):

```go
// WithAPIOptions is a helper function to construct functional options
// that sets APIOptions on LoadOptions. If APIOptions is set to nil, the
// APIOptions value is ignored. If multiple WithAPIOptions calls are
// made, the last call overrides the previous call values.
func WithAPIOptions(v []func(*middleware.Stack) error) LoadOptionsFunc {
	return func(o *LoadOptions) error {
		if v == nil {
			return nil
		}

		o.APIOptions = append(o.APIOptions, v...)
		return nil
	}
}
```

So `config.WithAPIOptions([]func(*middleware.Stack) error{prismaairs.APIOption(cfg)})`
protects **every client later built from that `aws.Config`** — including
clients for other AWS services, where the middleware is a harmless no-op
because it type-switches on the four Bedrock Runtime input types
(`*ConverseInput`, `*ConverseStreamInput`, `*InvokeModelInput`,
`*InvokeModelWithResponseStreamInput`) and forwards everything else
untouched.

Two registration cautions, from the source:

* `InitializeStep.Add` no longer rejects duplicate IDs
  (`step_initialize.go`, lines 128–131: "Add never returns an error. It used
  to for duplicate phases but this behavior has since been removed as part of
  a performance optimization.") — attaching the hook both per-config **and**
  per-client would scan twice. Attach it once.
* The hook registers with `middleware.After` on the Initialize step, which
  places it after the SDK's own `validateOpConverse`-style input validators
  (`validators.go`, line 218: `stack.Initialize.Add(&validateOpConverse{},
  middleware.After)` — validators are registered before `APIOptions` run).
  Invalid input therefore fails with the SDK's genuine validation error
  before any scan is attempted.
