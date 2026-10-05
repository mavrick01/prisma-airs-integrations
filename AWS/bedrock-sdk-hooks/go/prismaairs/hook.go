// Package prismaairs is a Prisma AIRS scan middleware for the AWS SDK for Go
// v2 Bedrock Runtime client.
//
// It registers on the SDK's smithy middleware stack so that EVERY Bedrock
// model invocation made through a protected client -- including calls a
// framework makes on the application's behalf -- is scanned by Prisma AIRS:
//
//   - prompt leg   the outbound prompt is scanned at the Initialize step; a
//     blocked prompt never leaves the process (the request is
//     not serialized, not signed, and never billed -- the rest
//     of the middleware stack is skipped)
//   - response leg the model's response is scanned after the stack unwinds,
//     before the application sees it; a blocked response is
//     withheld
//
// A Bedrock guardrail is a request parameter: every call site must remember
// to pass it, and a call without it is silently unguarded. This middleware is
// registered on the client (or on the shared aws.Config, covering every
// client built from it) and applies to every call made through it.
//
// Single file, depends only on the AWS SDK for Go v2 (which the application
// already has) and the standard library. Works with Converse, ConverseStream,
// InvokeModel, and InvokeModelWithResponseStream.
//
// Environment variables (standard Prisma AIRS names):
//
//	PRISMA_AIRS_API_KEY        required   API key from Strata Cloud Manager
//	PRISMA_AIRS_PROFILE_NAME   required   security profile name (or set ProfileName)
//	PRISMA_AIRS_URL            optional   regional endpoint, defaults to the US region
//
// Usage:
//
//	client := bedrockruntime.NewFromConfig(awsCfg,
//	    prismaairs.WithProtection(prismaairs.Config{AppName: "support-chat"}))
//
//	client.Converse(ctx, ...)   // scanned, both directions
//
// Or protect every client built from a shared aws.Config:
//
//	awsCfg, err := config.LoadDefaultConfig(ctx,
//	    config.WithAPIOptions([]func(*middleware.Stack) error{
//	        prismaairs.APIOption(prismaairs.Config{AppName: "support-chat"}),
//	    }))
package prismaairs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/smithy-go/middleware"
)

// DefaultEndpoint is the US-region Prisma AIRS API endpoint, used when
// PRISMA_AIRS_URL is not set.
const DefaultEndpoint = "https://service.api.aisecurity.paloaltonetworks.com"

const (
	scanPath       = "/v1/scan/sync/request"
	defaultTimeout = 10 * time.Second

	// Repo convention: app_name identifies the integration, and users append
	// their own application name after it ("AWS-Bedrock-support-chat").
	appNamePrefix = "AWS-Bedrock"
)

// --------------------------------------------------------------------------
// configuration
// --------------------------------------------------------------------------

// BlockMode selects how a block verdict is delivered to the caller.
type BlockMode int

const (
	// BlockRaise (the zero value) returns a *BlockedError from the operation,
	// reachable through errors.As.
	BlockRaise BlockMode = iota
	// BlockRespond substitutes a well-formed response whose text states the
	// block: a content_filtered Converse reply, or a JSON body for
	// InvokeModel. The two streaming operations cannot be fabricated (their
	// event stream field is unexported in the SDK), so they fall back to
	// BlockRaise -- see seam-notes.md.
	BlockRespond
)

// FailureMode selects the posture when a scan cannot produce a verdict.
type FailureMode int

const (
	// Block (the zero value) fails closed: the model call does not proceed.
	Block FailureMode = iota
	// Allow fails open: the model call proceeds unscanned.
	Allow
)

// Toggle is a three-state switch for the two scan legs. Its zero value,
// ToggleDefault, means enabled -- both legs are on unless set to Off.
type Toggle int

const (
	// ToggleDefault leaves the leg enabled (the zero value).
	ToggleDefault Toggle = iota
	// On enables the leg explicitly.
	On
	// Off disables the leg.
	Off
)

// Config controls one attachment of the scan middleware. The zero value is a
// working, fail-closed configuration (given the environment variables above).
type Config struct {
	// AppName is appended to the integration prefix:
	// metadata.app_name = "AWS-Bedrock-<AppName>" (or "AWS-Bedrock" if empty).
	AppName string
	// ProfileName overrides PRISMA_AIRS_PROFILE_NAME.
	ProfileName string
	// ProfileID is the AI profile UUID; name or id must resolve.
	ProfileID string
	// SessionID is a conversation id for SCM session correlation; echoed in
	// every verdict.
	SessionID string
	// AppUser is the end-user identity for metadata.app_user.
	AppUser string
	// OnBlock selects BlockRaise (default) or BlockRespond.
	OnBlock BlockMode
	// OnVerdict, if set, observes every scan verdict (allow and block alike).
	OnVerdict func(leg string, verdict map[string]any)
	// OnError is the posture when AIRS is unreachable or errors: Block
	// (default, fail closed) or Allow.
	OnError FailureMode
	// OnUnscannable is the posture when no text can be extracted: Block
	// (default) or Allow.
	OnUnscannable FailureMode
	// StrictVerdict treats a detection-service timeout or error flagged
	// inside an allow verdict as an error, following OnError.
	StrictVerdict bool
	// ApplyMaskedData replaces the delivered response text with the masked
	// text on mask-and-allow DLP verdicts (response_masked_data.data). If the
	// masked text cannot be substituted, the response is withheld like a
	// response-leg block rather than delivered unmasked.
	ApplyMaskedData bool
	// ScanPrompt toggles the prompt leg (default on).
	ScanPrompt Toggle
	// ScanResponse toggles the response leg (default on).
	ScanResponse Toggle
	// Timeout caps each scan call (two scans per round trip). Zero means 10s.
	Timeout time.Duration
}

func (c Config) validate() error {
	if c.OnBlock != BlockRaise && c.OnBlock != BlockRespond {
		return errors.New("prismaairs: OnBlock must be BlockRaise or BlockRespond")
	}
	if c.OnError != Block && c.OnError != Allow {
		return errors.New("prismaairs: OnError must be Block or Allow")
	}
	if c.OnUnscannable != Block && c.OnUnscannable != Allow {
		return errors.New("prismaairs: OnUnscannable must be Block or Allow")
	}
	for _, t := range []Toggle{c.ScanPrompt, c.ScanResponse} {
		if t != ToggleDefault && t != On && t != Off {
			return errors.New("prismaairs: ScanPrompt/ScanResponse must be ToggleDefault, On, or Off")
		}
	}
	if c.Timeout < 0 {
		return errors.New("prismaairs: Timeout must not be negative")
	}
	return nil
}

// --------------------------------------------------------------------------
// the block surfaces
// --------------------------------------------------------------------------

// BlockedError is returned to the caller when a scan verdict blocks a model
// call. It travels inside the SDK's *smithy.OperationError wrapper, so
// recover it with errors.As:
//
//	var blocked *prismaairs.BlockedError
//	if errors.As(err, &blocked) { ... }
type BlockedError struct {
	// Leg is "prompt" or "response".
	Leg string
	// Category is the verdict category (e.g. "malicious", or "airs_error" /
	// "unscannable" for synthesized fail-closed verdicts).
	Category string
	// ScanID is the AIRS scan id, when the verdict carries one.
	ScanID string
	// TransactionID is the per-call transaction id echoed by the verdict.
	TransactionID string
	// Operation is the Bedrock operation name ("Converse", "InvokeModel", ...).
	Operation string
	// Verdict is the full verdict document.
	Verdict map[string]any
}

func (e *BlockedError) Error() string {
	op := e.Operation
	if op == "" {
		op = "a Bedrock call"
	}
	return fmt.Sprintf(
		"blocked by Prisma AIRS on the %s leg of %s (category=%s scan_id=%s transaction_id=%s)",
		e.Leg, op, e.Category, e.ScanID, e.TransactionID)
}

// BlockInfo is attached to the operation output's ResultMetadata when
// OnBlock is BlockRespond and a call was blocked -- the Go analogue of the
// boto3 hook's ResponseMetadata.PrismaAirs.
type BlockInfo struct {
	Blocked       bool
	Leg           string
	Category      string
	ScanID        string
	TransactionID string
}

type blockInfoKey struct{}

// GetBlockInfo reports whether a respond-mode block was applied to the
// operation whose ResultMetadata is given:
//
//	out, err := client.Converse(ctx, ...)
//	if info, ok := prismaairs.GetBlockInfo(out.ResultMetadata); ok { ... }
func GetBlockInfo(md middleware.Metadata) (BlockInfo, bool) {
	info, ok := md.Get(blockInfoKey{}).(BlockInfo)
	return info, ok
}

// --------------------------------------------------------------------------
// registration
// --------------------------------------------------------------------------

// WithProtection returns a client option that registers the scan middleware
// on one Bedrock Runtime client:
//
//	client := bedrockruntime.NewFromConfig(awsCfg, prismaairs.WithProtection(cfg))
func WithProtection(cfg Config) func(*bedrockruntime.Options) {
	apiOption := APIOption(cfg)
	return func(o *bedrockruntime.Options) {
		o.APIOptions = append(o.APIOptions, apiOption)
	}
}

// APIOption returns the raw middleware-stack mutator, for attachment at the
// aws.Config level -- every client later built from that config is protected:
//
//	awsCfg, err := config.LoadDefaultConfig(ctx,
//	    config.WithAPIOptions([]func(*middleware.Stack) error{prismaairs.APIOption(cfg)}))
//
// Clients for other AWS services built from the same config are unaffected:
// the middleware type-switches on the four Bedrock Runtime input types and
// forwards everything else untouched. Attach the hook once -- per client or
// per config, not both -- or every call is scanned twice.
func APIOption(cfg Config) func(*middleware.Stack) error {
	m := &scanMiddleware{cfg: cfg}
	return func(stack *middleware.Stack) error {
		if err := cfg.validate(); err != nil {
			return err
		}
		// After = the tail of the Initialize step: the prompt scan runs after
		// the SDK's own input validators, still before serialization, the
		// retry loop, SigV4 signing, and any network I/O (seam-notes.md).
		return stack.Initialize.Add(m, middleware.After)
	}
}

// --------------------------------------------------------------------------
// the middleware: prompt leg before next, response leg after
// --------------------------------------------------------------------------

type scanMiddleware struct {
	cfg Config
}

func (*scanMiddleware) ID() string { return "PrismaAirsScan" }

func (m *scanMiddleware) HandleInitialize(
	ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
) (out middleware.InitializeOutput, md middleware.Metadata, err error) {
	var operation, modelID, prompt string
	var streaming, invokeStyle, opaque bool

	switch params := in.Parameters.(type) {
	case *bedrockruntime.ConverseInput:
		operation = "Converse"
		modelID = aws.ToString(params.ModelId)
		prompt, opaque = extractSafely(func() (string, bool) {
			return promptFromConverse(params.System, params.Messages)
		})
	case *bedrockruntime.ConverseStreamInput:
		operation, streaming = "ConverseStream", true
		modelID = aws.ToString(params.ModelId)
		prompt, opaque = extractSafely(func() (string, bool) {
			return promptFromConverse(params.System, params.Messages)
		})
	case *bedrockruntime.InvokeModelInput:
		operation, invokeStyle = "InvokeModel", true
		modelID = aws.ToString(params.ModelId)
		prompt, opaque = extractSafely(func() (string, bool) {
			return promptFromInvokeBody(params.Body)
		})
	case *bedrockruntime.InvokeModelWithResponseStreamInput:
		operation, streaming, invokeStyle = "InvokeModelWithResponseStream", true, true
		modelID = aws.ToString(params.ModelId)
		prompt, opaque = extractSafely(func() (string, bool) {
			return promptFromInvokeBody(params.Body)
		})
	default:
		// Not a model invocation (or not this service at all); pass through.
		return next.HandleInitialize(ctx, in)
	}

	transactionID := newTransactionID()

	// scannedPrompt is the prompt AIRS has already seen on the prompt leg; it
	// is the only text the response leg may re-send as context. With
	// ScanPrompt: Off nothing from the request is transmitted at all.
	scannedPrompt := ""

	// -- leg 1: before the request is serialized, signed, or sent ----------
	if m.cfg.ScanPrompt != Off {
		if opaque && m.cfg.OnUnscannable == Block {
			// Documents, images, video, audio -- or a content shape this
			// package does not recognize -- ride in this request; they cannot
			// be inspected as text, so the fail-closed posture governs, even
			// when scannable text is present alongside.
			logLeg("prompt", "unscannable", transactionID, 0, nil, "", operation,
				"content that cannot be inspected as text")
			verdict := map[string]any{"action": "block", "category": "unscannable"}
			return m.blockPrompt(operation, verdict, transactionID, streaming, invokeStyle)
		}
		if strings.TrimSpace(prompt) == "" {
			logLeg("prompt", "unscannable", transactionID, 0, nil, "", operation, "")
			if m.cfg.OnUnscannable == Block {
				verdict := map[string]any{"action": "block", "category": "unscannable"}
				return m.blockPrompt(operation, verdict, transactionID, streaming, invokeStyle)
			}
		} else {
			blocked, _ := m.runLeg(ctx, "prompt", map[string]string{"prompt": prompt},
				transactionID, operation, modelID)
			if blocked != nil {
				return m.blockPrompt(operation, blocked, transactionID, streaming, invokeStyle)
			}
			scannedPrompt = prompt
		}
	}

	out, md, err = next.HandleInitialize(ctx, in)

	// -- leg 2: after the stack has unwound, before the caller sees it -----
	if err != nil {
		// An AWS error response carries no model output; scanning or blocking
		// it would only mask the real error the SDK is about to return.
		return out, md, err
	}
	if m.cfg.ScanResponse == Off {
		return out, md, nil
	}
	if streaming {
		// The body is an event stream still on the wire; there is nothing
		// complete to scan here. See the README's streaming section.
		logLeg("response", "skipped-stream", transactionID, 0, nil, "", operation, "")
		return out, md, nil
	}

	var responseText string
	switch result := out.Result.(type) {
	case *bedrockruntime.ConverseOutput:
		responseText, _ = extractSafely(func() (string, bool) {
			return responseFromConverse(result), false
		})
	case *bedrockruntime.InvokeModelOutput:
		responseText, _ = extractSafely(func() (string, bool) {
			return responseFromInvokeBody(result.Body), false
		})
	}
	if strings.TrimSpace(responseText) == "" {
		logLeg("response", "unscannable", transactionID, 0, nil, "", operation, "")
		if m.cfg.OnUnscannable == Block {
			verdict := map[string]any{"action": "block", "category": "unscannable"}
			return m.blockResponse(out, md, operation, verdict, transactionID)
		}
		return out, md, nil
	}

	contents := map[string]string{"response": responseText}
	if strings.TrimSpace(scannedPrompt) != "" {
		contents["prompt"] = scannedPrompt // prompt as context for the response scan
	}
	blocked, allowed := m.runLeg(ctx, "response", contents, transactionID, operation, modelID)
	if blocked != nil {
		return m.blockResponse(out, md, operation, blocked, transactionID)
	}
	if m.cfg.ApplyMaskedData {
		if masked := maskedResponseData(allowed); masked != "" {
			if substituteMaskedText(out, masked) {
				logLeg("response", "masked", transactionID, 0, nil, "", operation, "")
			} else {
				// Never deliver the unmasked original; withhold it exactly
				// like a response-leg block.
				logLeg("response", "mask-unappliable", transactionID, 0, nil, "", operation, "")
				return m.blockResponse(out, md, operation,
					map[string]any{"action": "block", "category": "mask_unappliable"}, transactionID)
			}
		}
	}
	return out, md, nil
}

// blockPrompt delivers a prompt-leg block: a *BlockedError, or in respond
// mode a fabricated well-formed output (non-streaming operations only).
func (m *scanMiddleware) blockPrompt(
	operation string, verdict map[string]any, transactionID string, streaming, invokeStyle bool,
) (middleware.InitializeOutput, middleware.Metadata, error) {
	var md middleware.Metadata
	if m.cfg.OnBlock == BlockRaise || streaming {
		// Streaming outputs cannot be fabricated: their event stream field is
		// unexported in the SDK, so respond mode falls back to raising for
		// ConverseStream and InvokeModelWithResponseStream (seam-notes.md).
		return middleware.InitializeOutput{}, md, newBlockedError("prompt", verdict, transactionID, operation)
	}
	message := fmt.Sprintf("This request was blocked by Prisma AIRS (prompt scan, category=%s, scan_id=%s).",
		stringField(verdict, "category"), stringField(verdict, "scan_id"))
	md.Set(blockInfoKey{}, BlockInfo{
		Blocked: true, Leg: "prompt",
		Category: stringField(verdict, "category"), ScanID: stringField(verdict, "scan_id"),
		TransactionID: transactionID,
	})
	if invokeStyle {
		body, _ := json.Marshal(map[string]any{"prisma_airs_blocked": true, "message": message})
		return middleware.InitializeOutput{Result: &bedrockruntime.InvokeModelOutput{
			Body:        body,
			ContentType: aws.String("application/json"),
		}}, md, nil
	}
	return middleware.InitializeOutput{Result: &bedrockruntime.ConverseOutput{
		Metrics: &types.ConverseMetrics{LatencyMs: aws.Int64(0)},
		Output: &types.ConverseOutputMemberMessage{Value: types.Message{
			Role:    types.ConversationRoleAssistant,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: message}},
		}},
		StopReason: types.StopReasonContentFiltered,
		Usage: &types.TokenUsage{
			InputTokens: aws.Int32(0), OutputTokens: aws.Int32(0), TotalTokens: aws.Int32(0),
		},
	}}, md, nil
}

// blockResponse delivers a response-leg block: a *BlockedError, or in respond
// mode the real output rewritten in place.
func (m *scanMiddleware) blockResponse(
	out middleware.InitializeOutput, md middleware.Metadata,
	operation string, verdict map[string]any, transactionID string,
) (middleware.InitializeOutput, middleware.Metadata, error) {
	if m.cfg.OnBlock == BlockRaise {
		return middleware.InitializeOutput{}, md, newBlockedError("response", verdict, transactionID, operation)
	}
	message := fmt.Sprintf("The model response was withheld by Prisma AIRS (category=%s, scan_id=%s).",
		stringField(verdict, "category"), stringField(verdict, "scan_id"))
	if !replaceResponseText(out, message) {
		// Nothing recognizable to rewrite; withhold by raising instead.
		return middleware.InitializeOutput{}, md, newBlockedError("response", verdict, transactionID, operation)
	}
	if result, ok := out.Result.(*bedrockruntime.ConverseOutput); ok {
		result.StopReason = types.StopReasonContentFiltered
	}
	md.Set(blockInfoKey{}, BlockInfo{
		Blocked: true, Leg: "response",
		Category: stringField(verdict, "category"), ScanID: stringField(verdict, "scan_id"),
		TransactionID: transactionID,
	})
	return out, md, nil
}

// --------------------------------------------------------------------------
// one scan leg: build payload, call AIRS, interpret the verdict
// --------------------------------------------------------------------------

// runLeg returns (blockedVerdict, allowedVerdict); exactly one is non-nil
// unless the leg is skipped by an Allow failure posture (then both are nil).
func (m *scanMiddleware) runLeg(
	ctx context.Context, leg string, contents map[string]string,
	transactionID, operation, modelID string,
) (blocked, allowed map[string]any) {
	apiKey := os.Getenv("PRISMA_AIRS_API_KEY")
	profile := m.cfg.ProfileName
	if profile == "" {
		profile = os.Getenv("PRISMA_AIRS_PROFILE_NAME")
	}
	endpoint := os.Getenv("PRISMA_AIRS_URL")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	aiProfile := map[string]any{}
	if m.cfg.ProfileID != "" {
		aiProfile["profile_id"] = m.cfg.ProfileID
	}
	if profile != "" {
		aiProfile["profile_name"] = profile
	}
	if apiKey == "" || len(aiProfile) == 0 {
		reason := "PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME not set"
		logLeg(leg, "error", transactionID, 0, nil, reason, operation, "")
		if m.cfg.OnError == Block {
			return map[string]any{"action": "block", "category": "airs_error", "error": reason}, nil
		}
		return nil, nil
	}

	appName := appNamePrefix
	if m.cfg.AppName != "" {
		appName = appNamePrefix + "-" + m.cfg.AppName
	}
	metadata := map[string]any{"app_name": appName}
	if m.cfg.AppUser != "" {
		metadata["app_user"] = m.cfg.AppUser
	}
	if modelID != "" {
		metadata["ai_model"] = modelID
	}
	payload := map[string]any{
		"transaction_id": transactionID,
		"ai_profile":     aiProfile,
		"metadata":       metadata,
		"contents":       []map[string]string{contents},
	}
	if m.cfg.SessionID != "" {
		payload["session_id"] = m.cfg.SessionID
	}

	timeout := m.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	started := time.Now()
	verdict, scanErr := scanRequest(ctx, endpoint, apiKey, payload, timeout)
	elapsed := float64(time.Since(started).Microseconds()) / 1000.0

	var action string
	if scanErr == "" {
		raw, ok := verdict["action"]
		if !ok {
			scanErr = "scan response carries no action verdict"
		} else {
			action = strings.ToLower(fmt.Sprintf("%v", raw))
			if action != "allow" && action != "block" {
				scanErr = fmt.Sprintf("unknown scan action %q", action)
			}
		}
	}
	if scanErr == "" && m.cfg.StrictVerdict && action == "allow" {
		category := strings.ToLower(stringField(verdict, "category"))
		if truthy(verdict["timeout"]) || truthy(verdict["error"]) ||
			category == "error" || category == "timeout" {
			scanErr = fmt.Sprintf("degraded scan under StrictVerdict (timeout=%v error=%v)",
				verdict["timeout"], verdict["error"])
		}
	}
	if scanErr != "" {
		logLeg(leg, "error", transactionID, elapsed, nil, scanErr, operation, "")
		if m.cfg.OnError == Block {
			return map[string]any{"action": "block", "category": "airs_error", "error": scanErr}, nil
		}
		return nil, nil
	}

	logLeg(leg, action, transactionID, elapsed, verdict, "", operation, "")
	if m.cfg.OnVerdict != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					warning, _ := json.Marshal(map[string]any{
						"warning": "OnVerdict callback panicked", "error": fmt.Sprintf("%v", r)})
					log.Printf("prisma_airs %s", warning)
				}
			}()
			m.cfg.OnVerdict(leg, verdict)
		}()
	}
	if action == "block" {
		return verdict, nil
	}
	return nil, verdict
}

// --------------------------------------------------------------------------
// the scan call (same hardened client as the other AWS integrations)
// --------------------------------------------------------------------------

// A redirect would re-send x-pan-token to whatever host the 3xx names; refuse.
var scanHTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("prisma airs: refusing to follow redirect")
	},
}

// scanRequest POSTs one payload to the AIRS sync-scan endpoint and returns
// the parsed verdict, or a non-empty error description.
func scanRequest(
	ctx context.Context, endpoint, apiKey string, payload map[string]any, timeout time.Duration,
) (map[string]any, string) {
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return nil, fmt.Sprintf("refusing non-HTTPS endpoint: %s", endpoint)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Sprintf("scan payload not serializable: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(endpoint, "/")+scanPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Sprintf("scan failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-pan-token", apiKey)
	resp, err := scanHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Sprintf("network error reaching AIRS: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Sprintf("reading AIRS response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(raw)
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		return nil, fmt.Sprintf("HTTP %d from AIRS: %s", resp.StatusCode, snippet)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		return nil, "unexpected scan response shape"
	}
	return parsed, ""
}

// --------------------------------------------------------------------------
// prompt / response extraction per Bedrock operation
// --------------------------------------------------------------------------

// extractSafely runs one extractor under a recover() net. Request and response
// shapes are built by the caller and by the service, not by this package: a
// member left nil, or one whose marshaller misbehaves, must never take the
// caller's own Bedrock call down with it. A panicking extraction degrades to
// "no text, unscannable", so the configured OnUnscannable posture -- fail
// closed by default -- decides what happens next.
func extractSafely(extract func() (string, bool)) (text string, opaque bool) {
	defer func() {
		if r := recover(); r != nil {
			warning, _ := json.Marshal(map[string]any{
				"warning": "content extraction panicked", "error": fmt.Sprintf("%v", r)})
			log.Printf("prisma_airs %s", warning)
			text, opaque = "", true
		}
	}()
	return extract()
}

// textsFromContent returns every scannable string in a content-block list --
// plain text, guardContent text, the tool call the model is asking for,
// toolResult text/JSON, reasoning text, retrieved searchResult passages and
// cited content -- and whether any block carries a payload that cannot be
// inspected as text. The switch is an allowlist: documents, images, video and
// audio are opaque, and so is any block shape it does not recognize, so a
// content type Bedrock adds later fails closed instead of vanishing from the
// scan while the leg still reports a clean allow.
func textsFromContent(content []types.ContentBlock) (texts []string, opaque bool) {
	for _, block := range content {
		switch b := block.(type) {
		case *types.ContentBlockMemberText:
			texts = append(texts, b.Value)
		case *types.ContentBlockMemberGuardContent:
			if t, ok := guardContentText(b.Value); ok {
				texts = append(texts, t)
			} else {
				opaque = true // a guardContent image, not text
			}
		case *types.ContentBlockMemberToolUse:
			// The action the model is asking the application to take: the
			// tool name plus its arguments, serialized exactly as a
			// toolResult JSON block is.
			if name := aws.ToString(b.Value.Name); name != "" {
				texts = append(texts, name)
			}
			if data, err := marshalDocument(b.Value.Input); err == nil {
				texts = append(texts, data)
			} else {
				opaque = true
			}
		case *types.ContentBlockMemberToolResult:
			t, o := textsFromToolResult(b.Value.Content)
			texts = append(texts, t...)
			opaque = opaque || o
		case *types.ContentBlockMemberReasoningContent:
			if r, ok := b.Value.(*types.ReasoningContentBlockMemberReasoningText); ok {
				texts = append(texts, aws.ToString(r.Value.Text))
			} else {
				opaque = true // reasoning the provider encrypted
			}
		case *types.ContentBlockMemberSearchResult:
			texts = append(texts, searchResultTexts(b.Value)...)
		case *types.ContentBlockMemberCitationsContent:
			t, o := citationsTexts(b.Value)
			texts = append(texts, t...)
			opaque = opaque || o
		case *types.ContentBlockMemberCachePoint:
			// A prompt-cache marker: it carries no content, so there is
			// nothing to extract and nothing hidden from the scan.
		case *types.ContentBlockMemberDocument, *types.ContentBlockMemberImage,
			*types.ContentBlockMemberVideo, *types.ContentBlockMemberAudio:
			opaque = true
		default:
			opaque = true // any block type added to the API after this was written
		}
	}
	return texts, opaque
}

// textsFromToolResult walks the sub-blocks a tool returned. Note that
// types.ToolResultContentBlock has no audio member -- the default covers
// whatever the API adds here later.
func textsFromToolResult(content []types.ToolResultContentBlock) (texts []string, opaque bool) {
	for _, raw := range content {
		switch sub := raw.(type) {
		case *types.ToolResultContentBlockMemberText:
			texts = append(texts, sub.Value)
		case *types.ToolResultContentBlockMemberJson:
			if data, err := marshalDocument(sub.Value); err == nil {
				texts = append(texts, data)
			} else {
				opaque = true
			}
		case *types.ToolResultContentBlockMemberSearchResult:
			texts = append(texts, searchResultTexts(sub.Value)...)
		case *types.ToolResultContentBlockMemberDocument,
			*types.ToolResultContentBlockMemberImage,
			*types.ToolResultContentBlockMemberVideo:
			opaque = true
		default:
			opaque = true
		}
	}
	return texts, opaque
}

// marshalDocument serializes a smithy document member. The nil check is not
// defensive style: the SDK does not validate the JSON member of a toolResult
// block, so an application that assembled one without a document (a tool that
// errored before assigning it) reaches here with a nil interface, and calling
// through it would panic the caller's goroutine before any scan ran. An
// unusable document is treated as content that cannot be inspected.
func marshalDocument(doc document.Interface) (string, error) {
	if doc == nil {
		return "", errors.New("nil document")
	}
	data, err := doc.MarshalSmithyDocument()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// searchResultTexts returns the passages a searchResult block carries.
// Retrieved third-party text is the canonical indirect-injection carrier, so
// it is scanned exactly like any other text the request delivers.
func searchResultTexts(sr types.SearchResultBlock) []string {
	var texts []string
	for _, block := range sr.Content {
		if t := aws.ToString(block.Text); t != "" {
			texts = append(texts, t)
		}
	}
	return texts
}

// citationsTexts returns what a citationsContent block delivers: the model's
// generated answer, plus the source passages that answer cites.
func citationsTexts(cc types.CitationsContentBlock) (texts []string, opaque bool) {
	for _, generated := range cc.Content {
		if t, ok := generated.(*types.CitationGeneratedContentMemberText); ok {
			texts = append(texts, t.Value)
		} else {
			opaque = true
		}
	}
	for _, citation := range cc.Citations {
		for _, source := range citation.SourceContent {
			if t, ok := source.(*types.CitationSourceContentMemberText); ok {
				texts = append(texts, t.Value)
			} else {
				opaque = true
			}
		}
	}
	return texts, opaque
}

// guardContentText returns the text of a guardContent block; the false return
// means the block carries something else (an image), which every call site
// treats as opaque.
func guardContentText(gc types.GuardrailConverseContentBlock) (string, bool) {
	if t, ok := gc.(*types.GuardrailConverseContentBlockMemberText); ok {
		return aws.ToString(t.Value.Text), true
	}
	return "", false
}

// promptFromConverse returns the system prompt and every user-role message --
// EVERY one, not just the newest; a single call can smuggle instructions in
// any of them -- and whether content that cannot be inspected as text rides
// along. Assistant-role turns are not walked.
func promptFromConverse(system []types.SystemContentBlock, messages []types.Message) (string, bool) {
	var texts []string
	opaque := false
	for _, block := range system {
		switch b := block.(type) {
		case *types.SystemContentBlockMemberText:
			texts = append(texts, b.Value)
		case *types.SystemContentBlockMemberGuardContent:
			if t, ok := guardContentText(b.Value); ok {
				texts = append(texts, t)
			} else {
				opaque = true // a guardContent image, not text
			}
		case *types.SystemContentBlockMemberCachePoint:
			// A prompt-cache marker: no content, nothing hidden.
		default:
			opaque = true // any system block type added to the API later
		}
	}
	for _, message := range messages {
		if message.Role != types.ConversationRoleUser {
			continue
		}
		t, o := textsFromContent(message.Content)
		texts = append(texts, t...)
		opaque = opaque || o
	}
	return strings.Join(texts, "\n"), opaque
}

// responseFromConverse returns the scannable text of a Converse output's
// assistant message, including any tool call it is asking the application to
// make.
func responseFromConverse(out *bedrockruntime.ConverseOutput) string {
	message, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return ""
	}
	texts, _ := textsFromContent(message.Value.Content)
	return strings.Join(texts, "\n")
}

// replaceResponseText withholds the model's output and puts the given notice
// in its place: the whole content list becomes one text block, which is what a
// respond-mode block wants -- nothing of the original may survive. Masked
// delivery uses substituteMaskedText instead. Returns false when the output
// shape is not recognized.
func replaceResponseText(out middleware.InitializeOutput, text string) bool {
	switch result := out.Result.(type) {
	case *bedrockruntime.ConverseOutput:
		result.Output = &types.ConverseOutputMemberMessage{Value: types.Message{
			Role:    types.ConversationRoleAssistant,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: text}},
		}}
		return true
	case *bedrockruntime.InvokeModelOutput:
		body, _ := json.Marshal(map[string]any{"prisma_airs": "response replaced", "text": text})
		result.Body = body
		result.ContentType = aws.String("application/json")
		return true
	}
	return false
}

// substituteMaskedText writes masked text back into the response the caller
// will see, leaving every other content block in place. Collapsing the content
// list the way a block does would delete a toolUse block from a turn AIRS
// allowed, stranding an agent loop with stopReason "tool_use" and nothing to
// call. The masked text carries the whole message, so the first text block
// takes it and any further text blocks are blanked rather than left holding
// unmasked copies. Returns false when there is no text block to substitute
// into -- the caller then withholds the response instead of delivering it
// unmasked.
func substituteMaskedText(out middleware.InitializeOutput, masked string) bool {
	result, ok := out.Result.(*bedrockruntime.ConverseOutput)
	if !ok {
		// An InvokeModel body is opaque JSON with no typed block to rewrite
		// in place; it is replaced whole, as documented.
		return replaceResponseText(out, masked)
	}
	message, ok := result.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return false
	}
	substituted := false
	for _, block := range message.Value.Content {
		text, ok := block.(*types.ContentBlockMemberText)
		if !ok {
			continue
		}
		if substituted {
			text.Value = ""
			continue
		}
		text.Value = masked
		substituted = true
	}
	return substituted
}

// maskedResponseData returns the masked replacement text a mask-and-allow
// verdict carries (response_masked_data.data), or "".
func maskedResponseData(verdict map[string]any) string {
	if verdict == nil {
		return ""
	}
	masked, ok := verdict["response_masked_data"].(map[string]any)
	if !ok {
		return ""
	}
	data, _ := masked["data"].(string)
	return data
}

// Model families speak different body dialects through InvokeModel. Known
// families get precise extraction; anything unknown falls back to scanning
// the entire serialized body, which errs toward inspecting too much rather
// than too little.
func promptFromInvokeBody(raw []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", false
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return trimmed, false // not a JSON object: scan the raw body text
	}
	if _, ok := body["messages"].([]any); ok { // messages-array dialects + amazon nova
		prompt, opaque := promptFromGenericConverseBody(body)
		if prompt != "" || opaque {
			return prompt, opaque
		}
	}
	if _, ok := body["message"].(string); ok { // cohere chat
		prompt, opaque := promptFromCohereBody(body)
		if prompt != "" || opaque {
			return prompt, opaque
		}
	}
	for _, key := range []string{"inputText", "prompt"} { // titan / llama, mistral
		if s, ok := body[key].(string); ok && strings.TrimSpace(s) != "" {
			return s, false
		}
	}
	return trimmed, false // unknown dialect: scan everything
}

// promptFromCohereBody extracts a Cohere chat body: the newest message plus
// the conversation history, the retrieved documents, and any tool results the
// application is feeding back. Taking only the newest message would leave the
// retrieved and returned text -- the indirect-injection carriers -- unscanned.
func promptFromCohereBody(body map[string]any) (string, bool) {
	var texts []string
	opaque := false
	if message, ok := body["message"].(string); ok && strings.TrimSpace(message) != "" {
		texts = append(texts, message)
	}
	history, _ := body["chat_history"].([]any)
	for _, raw := range history {
		turn, ok := raw.(map[string]any)
		if !ok {
			opaque = true
			continue
		}
		if message, ok := turn["message"].(string); ok && strings.TrimSpace(message) != "" {
			texts = append(texts, message)
		}
	}
	for _, key := range []string{"documents", "tool_results"} {
		items, ok := body[key].([]any)
		if !ok || len(items) == 0 {
			continue
		}
		data, err := json.Marshal(items)
		if err != nil {
			opaque = true
			continue
		}
		texts = append(texts, string(data))
	}
	return strings.Join(texts, "\n"), opaque
}

// promptFromGenericConverseBody mirrors promptFromConverse over a parsed
// messages-array body: the top-level "system" field (string or content list)
// plus every user-role message, with the opaque flag for anything the walker
// cannot read as text.
func promptFromGenericConverseBody(body map[string]any) (string, bool) {
	var texts []string
	opaque := false
	switch system := body["system"].(type) {
	case string:
		if strings.TrimSpace(system) != "" {
			texts = append(texts, system)
		}
	case []any:
		t, o := textsFromGenericContent(system)
		texts = append(texts, t...)
		opaque = opaque || o
	case nil:
		// No system field at all.
	default:
		opaque = true // a system field in a shape this walker does not know
	}
	messages, _ := body["messages"].([]any)
	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok || msg["role"] != "user" {
			continue
		}
		if content, ok := msg["content"].(string); ok {
			if strings.TrimSpace(content) != "" {
				texts = append(texts, content)
			}
			continue
		}
		t, o := textsFromGenericContent(msg["content"])
		texts = append(texts, t...)
		opaque = opaque || o
	}
	return strings.Join(texts, "\n"), opaque
}

// textsFromGenericContent mirrors textsFromContent over a parsed JSON content
// list. Two dialects share this position and both are walked here: a
// Converse-style body names each block by KEY ({"text": ...},
// {"toolResult": {...}}), while the messages dialect names it in a "type"
// field ({"type": "tool_result", ...}) -- a body in the second dialect used to
// match nothing at all, so an injected tool result reached the model with the
// leg reporting a clean allow.
func textsFromGenericContent(content any) (texts []string, opaque bool) {
	items, ok := content.([]any)
	if !ok {
		// No content list at all carries nothing to inspect; any other shape
		// is an unrecognized dialect and fails closed.
		return nil, content != nil
	}
	for _, item := range items {
		block, ok := item.(map[string]any)
		if !ok {
			opaque = true
			continue
		}
		t, o := textsFromGenericBlock(block)
		texts = append(texts, t...)
		opaque = opaque || o
	}
	return texts, opaque
}

// textsFromGenericBlock walks one parsed content block of either dialect. Like
// the typed walker it is an allowlist: a block matching neither vocabulary is
// opaque, so an unknown shape follows the OnUnscannable posture instead of
// being dropped silently.
func textsFromGenericBlock(block map[string]any) (texts []string, opaque bool) {
	// The messages dialect: the block names its own type.
	switch block["type"] {
	case "text":
		return genericString(block["text"])
	case "thinking":
		return genericString(block["thinking"])
	case "tool_use":
		return genericToolUseTexts(block)
	case "tool_result":
		// The result of a tool the model called: a plain string, or a nested
		// content list in either dialect.
		if s, ok := block["content"].(string); ok {
			return []string{s}, false
		}
		return textsFromGenericContent(block["content"])
	case "redacted_thinking", "image", "document", "video", "audio":
		return nil, true
	}

	// A Converse-style body: the block is named by its key.
	if raw, present := block["text"]; present {
		return genericString(raw)
	}
	if raw, present := block["json"]; present { // a toolResult sub-block
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, true
		}
		return []string{string(data)}, false
	}
	if raw, present := block["guardContent"]; present {
		gc, ok := raw.(map[string]any)
		if !ok {
			return nil, true
		}
		tb, _ := gc["text"].(map[string]any)
		if s, ok := tb["text"].(string); ok {
			return []string{s}, false
		}
		return nil, true // a guardContent image, or a member added later
	}
	if raw, present := block["toolUse"]; present {
		return genericToolUseTexts(raw)
	}
	if raw, present := block["toolResult"]; present {
		tr, ok := raw.(map[string]any)
		if !ok {
			return nil, true
		}
		return textsFromGenericContent(tr["content"])
	}
	if raw, present := block["reasoningContent"]; present {
		rc, ok := raw.(map[string]any)
		if !ok {
			return nil, true
		}
		if rt, ok := rc["reasoningText"].(map[string]any); ok {
			if s, ok := rt["text"].(string); ok {
				return []string{s}, false
			}
		}
		return nil, true // reasoning the provider encrypted, or a member added later
	}
	if raw, present := block["searchResult"]; present {
		sr, ok := raw.(map[string]any)
		if !ok {
			return nil, true
		}
		return textsFromGenericContent(sr["content"])
	}
	if raw, present := block["citationsContent"]; present {
		return genericCitationsTexts(raw)
	}
	if _, present := block["cachePoint"]; present {
		return nil, false // a prompt-cache marker, not content
	}
	// Documents, images, video, audio -- and any block shape added later.
	return nil, true
}

// genericString extracts a block member that has to be a string; anything else
// is a shape this walker does not understand.
func genericString(value any) ([]string, bool) {
	if s, ok := value.(string); ok {
		return []string{s}, false
	}
	return nil, true
}

// genericToolUseTexts extracts the tool call a model is asking for -- the name
// plus its serialized arguments -- from either dialect: the messages dialect
// carries them on the block itself, a Converse-style body inside "toolUse".
func genericToolUseTexts(raw any) (texts []string, opaque bool) {
	tu, ok := raw.(map[string]any)
	if !ok {
		return nil, true
	}
	if name, ok := tu["name"].(string); ok && name != "" {
		texts = append(texts, name)
	}
	if input, present := tu["input"]; present {
		data, err := json.Marshal(input)
		if err != nil {
			return texts, true
		}
		texts = append(texts, string(data))
	}
	if len(texts) == 0 {
		return nil, true // a tool call naming neither a tool nor its arguments
	}
	return texts, false
}

// genericCitationsTexts mirrors citationsTexts over a parsed citationsContent
// block: the generated answer, plus the source passages it cites.
func genericCitationsTexts(raw any) (texts []string, opaque bool) {
	cc, ok := raw.(map[string]any)
	if !ok {
		return nil, true
	}
	texts, opaque = textsFromGenericContent(cc["content"])
	citations, _ := cc["citations"].([]any)
	for _, item := range citations {
		citation, ok := item.(map[string]any)
		if !ok {
			opaque = true
			continue
		}
		t, o := textsFromGenericContent(citation["sourceContent"])
		texts = append(texts, t...)
		opaque = opaque || o
	}
	return texts, opaque
}

// responseFromInvokeBody extracts the model output text from an InvokeModel
// response body, falling back to the raw body for unknown dialects.
func responseFromInvokeBody(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return trimmed
	}
	if text := invokeResponseFromParsed(body); text != "" {
		return text
	}
	return trimmed
}

func invokeResponseFromParsed(body map[string]any) string {
	if content, ok := body["content"].([]any); ok { // messages-API content list
		if texts, _ := textsFromGenericContent(content); len(texts) > 0 {
			return strings.Join(texts, "\n")
		}
	}
	if output, ok := body["output"].(map[string]any); ok { // nova
		if message, ok := output["message"].(map[string]any); ok {
			if texts, _ := textsFromGenericContent(message["content"]); len(texts) > 0 {
				return strings.Join(texts, "\n")
			}
		}
	}
	if results, ok := body["results"].([]any); ok && len(results) > 0 { // titan
		if first, ok := results[0].(map[string]any); ok {
			if s, ok := first["outputText"].(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	for _, key := range []string{"generation", "outputs", "text", "completion"} { // llama / mistral / cohere
		switch value := body[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return value
			}
		case []any:
			if len(value) > 0 {
				if first, ok := value[0].(map[string]any); ok {
					if s, ok := first["text"].(string); ok && strings.TrimSpace(s) != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// --------------------------------------------------------------------------
// shared plumbing
// --------------------------------------------------------------------------

func newBlockedError(leg string, verdict map[string]any, transactionID, operation string) *BlockedError {
	return &BlockedError{
		Leg:           leg,
		Category:      stringField(verdict, "category"),
		ScanID:        stringField(verdict, "scan_id"),
		TransactionID: transactionID,
		Operation:     operation,
		Verdict:       verdict,
	}
}

// newTransactionID returns a version-4 UUID from crypto/rand.
func newTransactionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails on supported platforms
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func truthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0
	default:
		return true
	}
}

// logLeg writes one line per scan leg: `prisma_airs {json}` with the
// operation name, transaction id, detection flags, and latency.
func logLeg(leg, action, transactionID string, elapsedMs float64, verdict map[string]any, scanErr, operation, note string) {
	record := map[string]any{
		"leg":            leg,
		"action":         action,
		"transaction_id": transactionID,
		"ms":             math.Round(elapsedMs*10) / 10,
	}
	if note != "" {
		record["note"] = note
	}
	if operation != "" {
		record["operation"] = operation
	}
	if verdict != nil {
		record["category"] = verdict["category"]
		record["scan_id"] = verdict["scan_id"]
		record["report_id"] = verdict["report_id"]
		detected := map[string][]string{}
		for _, side := range []string{"prompt_detected", "response_detected"} {
			flags, ok := verdict[side].(map[string]any)
			if !ok {
				continue
			}
			var hits []string
			for name, value := range flags {
				if truthy(value) {
					hits = append(hits, name)
				}
			}
			if len(hits) > 0 {
				sort.Strings(hits)
				detected[side] = hits
			}
		}
		if len(detected) > 0 {
			record["detected"] = detected
		}
		if truthy(verdict["timeout"]) {
			record["timeout"] = true
		}
		if truthy(verdict["error"]) {
			record["error_flag"] = true
		}
	}
	if scanErr != "" {
		record["error"] = scanErr
	}
	line, err := json.Marshal(record)
	if err != nil {
		line = []byte(fmt.Sprintf(`{"leg":%q,"action":%q,"transaction_id":%q}`, leg, action, transactionID))
	}
	log.Printf("prisma_airs %s", line)
}
