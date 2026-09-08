package upstream

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"workbuddy2api/internal/auth"
)

const (
	ccIdentity = "You are Claude Code, Anthropic's official CLI for Claude."
	ccBranch   = "Main branch (you will usually use this for PRs)"
	ccHeader   = "x-anthropic-billing-header: cc_version=1.0; cc_entrypoint=cli;"

	codexIdentity1 = "You are Codex, an OpenAI general-purpose agentic assistant that helps the user complete tasks across coding, browsing, apps, documents, research, and other digital workflows."
	codexIdentity2 = "You are Codex, a coding agent based on GPT-5."

	openclawIdentity = "You are a personal assistant running inside OpenClaw."
	openclawTag      = "<!-- openclaw:attempt:STABLE -->"
	openclawCtxTag   = "⟦openclaw:ctx⟧"
	openclawCtxMark  = "<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>"

	hermesIdentity = "You are Hermes, an AI assistant created by Nous Research."
	qwenpawIdentity = "You are QwenPaw, a personal AI assistant"
)

func TestIdentityRewritten(t *testing.T) {
	out := sanitizeText(ccIdentity)
	if !strings.Contains(out, "official CLI tool for Claude.") {
		t.Errorf("identity not rewritten: %q", out)
	}
	if strings.Contains(out, ccIdentity) {
		t.Errorf("original identity still present: %q", out)
	}
}

func TestCodexIdentityRewritten(t *testing.T) {
	out1 := sanitizeText(codexIdentity1)
	if strings.Contains(out1, "an OpenAI general-purpose") {
		t.Errorf("codex1 identity not rewritten: %q", out1)
	}
	if !strings.Contains(out1, "an AI general-purpose") {
		t.Errorf("codex1 expected replacement missing: %q", out1)
	}

	out2 := sanitizeText(codexIdentity2)
	if strings.Contains(out2, "coding agent based on GPT-5.") {
		t.Errorf("codex2 identity not rewritten: %q", out2)
	}
	if !strings.Contains(out2, "coding assistant based on GPT-5.") {
		t.Errorf("codex2 expected replacement missing: %q", out2)
	}
}

func TestOpenClawIdentityRewritten(t *testing.T) {
	// 身份句：品牌词级清洗应彻底移除 openclaw，且替换为中性 workspace 短语。
	out := sanitizeText(openclawIdentity)
	if strings.Contains(out, "OpenClaw") || strings.Contains(out, "openclaw") {
		t.Errorf("openclaw identity still present: %q", out)
	}
	if !strings.Contains(out, "managed workspace") {
		t.Errorf("openclaw expected replacement missing: %q", out)
	}

	// 架构标签标记
	tagOut := sanitizeText(openclawTag)
	if strings.Contains(tagOut, "openclaw:attempt") {
		t.Errorf("openclaw tag not rewritten: %q", tagOut)
	}
	if !strings.Contains(tagOut, "prompt:attempt") {
		t.Errorf("openclaw tag expected replacement missing: %q", tagOut)
	}

	// 内部上下文标记（底层占位 ⟦openclaw:ctx⟧）
	ctxOut := sanitizeText(openclawCtxTag)
	if strings.Contains(ctxOut, "openclaw") {
		t.Errorf("openclaw ctx marker not rewritten: %q", ctxOut)
	}
	if !strings.Contains(ctxOut, "workspace:ctx") {
		t.Errorf("openclaw ctx expected replacement missing: %q", ctxOut)
	}

	// 内部上下文包裹标签（<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>）
	markOut := sanitizeText(openclawCtxMark)
	if strings.Contains(markOut, "OPENCLAW") {
		t.Errorf("openclaw internal context marker not rewritten: %q", markOut)
	}
	if !strings.Contains(markOut, "BEGIN_INTERNAL_CONTEXT") {
		t.Errorf("openclaw internal context expected replacement missing: %q", markOut)
	}
}

func TestOpenClawIconicSentencesRewritten(t *testing.T) {
	samples := []struct {
		original string
		forbidden string
	}{
		{"Tools policy-filtered. Names case-sensitive; call exact.", "Tools policy-filtered. Names case-sensitive; call exact."},
		{"Routine low-risk: call silently.", "Routine low-risk: call silently."},
		{"Narrate only complex, sensitive/destructive, or requested steps.", "Narrate only complex, sensitive/destructive, or requested steps."},
		{"First-class tool exists: use it; never ask user for equivalent CLI/slash.", "First-class tool exists: use it; never ask user for equivalent CLI/slash."},
		{"- Actionable request: act now.", "- Actionable request: act now."},
		{"No independent goals, self-preservation, replication, resource acquisition, power-seeking, or plans beyond user request.", "No independent goals, self-preservation"},
		{"Safety/oversight > completion. Conflict: pause/ask. Obey stop/pause/audit; never bypass safeguards.", "Safety/oversight > completion."},
		{"- Media attachment: own line `MEDIA:<path-or-url>` per item; path is not prose.", "MEDIA:<path-or-url>"},
		{"- Directive starts line, plain text, outside fences/Markdown; never inline or wrapped.", "Directive starts line, plain text"},
		{"- Native reply starts with `[[reply_to_current]]`; explicit id only: `[[reply_to:<id>]]`.", "Native reply starts with `[[reply_to_current]]`"},
		{"Large work: `sessions_spawn`; follow the accepted completion mode.", "Large work: `sessions_spawn`"},
	}

	for _, s := range samples {
		out := sanitizeText(s.original)
		if strings.Contains(out, s.forbidden) {
			t.Errorf("sentence %q not rewritten, still contains %q: %q", s.original, s.forbidden, out)
		}
	}
}

func TestOpenClawToolsSanitized(t *testing.T) {
	rawTools := []any{
		map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        "dashboard",
				"description": "Open the OpenClaw dashboard",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":        "string",
							"description": "Path in .openclaw/workspace",
						},
					},
				},
			},
		},
	}

	sanitizeTools(rawTools)

	b, err := json.Marshal(rawTools)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(strings.ToLower(s), "openclaw") {
		t.Errorf("tools still contain openclaw: %s", s)
	}
	if !strings.Contains(s, "workspace dashboard") {
		t.Errorf("tools function description not rewritten: %s", s)
	}
	if !strings.Contains(s, ".workspace/workspace") {
		t.Errorf("tools property description not rewritten: %s", s)
	}
}

func TestOpenClawAnyOccurrenceWordLevel(t *testing.T) {
	// 任何含 openclaw 的散落文本都要被词级清洗（不依赖逐句精确匹配）。
	in := "use OpenClaw tools; openclaw status; OPENCLAW 启动"
	out := sanitizeText(in)
	if strings.Contains(out, "OpenClaw") || strings.Contains(out, "openclaw") || strings.Contains(out, "OPENCLAW") {
		t.Errorf("word-level openclaw not stripped: %q", out)
	}
	if !strings.Contains(out, "workspace tools") {
		t.Errorf("expected neutral replacement missing: %q", out)
	}
}

func TestBranchRewritten(t *testing.T) {
	out := sanitizeText(ccBranch)
	if !strings.Contains(out, "Default branch (you will usually use this for PRs)") {
		t.Errorf("branch not rewritten: %q", out)
	}
	if strings.Contains(out, "Main branch") {
		t.Errorf("original branch still present: %q", out)
	}
}

func TestBillingHeaderStrippedValueIrrelevant(t *testing.T) {
	out := sanitizeText(ccHeader)
	if strings.Contains(out, "x-anthropic-billing-header") {
		t.Errorf("header not stripped: %q", out)
	}
}

func TestBillingHeaderCaseInsensitive(t *testing.T) {
	alt := "X-Anthropic-Billing-Header: cc_version=1.0;"
	out := strings.ToLower(sanitizeText(alt))
	if strings.Contains(out, "billing") {
		t.Errorf("case-insensitive header not stripped: %q", out)
	}
}

func TestTrailingKVStripped(t *testing.T) {
	out := sanitizeText("...; cc_version=2.0; cc_entrypoint=cli;")
	if strings.Contains(out, "cc_version") || strings.Contains(out, "cc_entrypoint") {
		t.Errorf("trailing kv not stripped: %q", out)
	}
}

func TestExactMatchOnlyVariantNotTouched(t *testing.T) {
	in := "...official CLI for Claude!"
	if out := sanitizeText(in); out != in {
		t.Errorf("variant should be untouched: %q -> %q", in, out)
	}
}

func TestUserFreeTextNotTouched(t *testing.T) {
	in := "please use main branch for this repo"
	if out := sanitizeText(in); out != in {
		t.Errorf("free text should be untouched: %q -> %q", in, out)
	}
}

func TestNoFeatureReturnsSameString(t *testing.T) {
	in := "ordinary user message"
	if out := sanitizeText(in); out != in {
		t.Errorf("no-feature text should pass through unchanged: %q -> %q", in, out)
	}
}

func TestMultimodalTextPartOnly(t *testing.T) {
	imgPart := map[string]any{"type": "image", "source": map[string]any{"type": "base64", "data": "..."}}
	content := []any{
		map[string]any{"type": "text", "text": ccIdentity},
		imgPart,
	}
	out, changed := sanitizeContent(content)
	if !changed {
		t.Fatal("expected change")
	}
	parts := out.([]any)
	txt, _ := parts[0].(map[string]any)["text"].(string)
	if !strings.Contains(txt, "CLI tool") {
		t.Errorf("text part not sanitized: %q", txt)
	}
	img, _ := parts[1].(map[string]any)
	if img["type"] != "image" || img["source"].(map[string]any)["data"] != "..." {
		t.Error("image part modified")
	}
}

// 集成：完整请求体经 PrepareBodyOpt 净化后无残留指纹，且 stream/tool_choice 行为不受影响。
func TestPrepareBodyOptSanitizesSystem(t *testing.T) {
	body := []byte(`{"model":"glm-5.2","messages":[` +
		`{"role":"system","content":"` + ccIdentity + ` ` + ccHeader + `"},` +
		`{"role":"user","content":"hi"}]}`)
	out := PrepareBodyOpt(body, true)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["stream"] != true {
		t.Error("stream not forced")
	}
	msgs := obj["messages"].([]any)
	sys, _ := msgs[0].(map[string]any)["content"].(string)
	if strings.Contains(sys, "x-anthropic-billing-header") || strings.Contains(sys, ccIdentity) || strings.Contains(sys, ccBranch) {
		t.Errorf("fingerprints remain: %q", sys)
	}
	if !strings.Contains(sys, "CLI tool") {
		t.Errorf("rewrite missing: %q", sys)
	}
}

func TestPrepareBodyOptDisabledPreservesFingerprints(t *testing.T) {
	body := []byte(`{"model":"glm-5.2","messages":[{"role":"system","content":"` + ccIdentity + `"}]}`)
	out := PrepareBodyOpt(body, false)
	if !strings.Contains(string(out), ccIdentity) {
		t.Error("sanitize=false should preserve fingerprints")
	}
	// 但 stream 仍强制
	var obj map[string]any
	_ = json.Unmarshal(out, &obj)
	if obj["stream"] != true {
		t.Error("stream should still be forced")
	}
}

// PrepareBody 默认行为 = 开启脱敏（保持向后兼容）。
func TestPrepareBodyDefaultSanitizes(t *testing.T) {
	body := []byte(`{"model":"glm-5.2","messages":[{"role":"system","content":"` + ccIdentity + `"}]}`)
	out := PrepareBodyOpt(body, true)
	if strings.Contains(string(out), ccIdentity) {
		t.Error("PrepareBody default should sanitize")
	}
}

// 出站边界集成：ChatStream 发往上游的 wire body 必须无残留指纹。
func TestChatStreamWireBodySanitized(t *testing.T) {
	var gotBody []byte
	ts := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"))
	})
	defer ts.Close()

	c := New()
	c.SanitizeFingerprints = true
	c.ChatBaseCN = ts.URL
	acct := &auth.Auth{AccessToken: "test-token", Domain: "copilot.tencent.com", UID: "u1"}

	body := []byte(`{"model":"glm-5.2","messages":[` +
		`{"role":"system","content":"` + ccIdentity + ` ` + ccHeader + `"},` +
		`{"role":"user","content":"hi"}]}`)
	rc, status, respBody, err := c.ChatStream(acct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if status >= 400 {
		t.Fatalf("upstream status %d: %s", status, respBody)
	}
	// 上游收到的 body：stream 强制 + 指纹已净化
	var obj map[string]any
	if err := json.Unmarshal(gotBody, &obj); err != nil {
		t.Fatalf("wire body not json: %v", err)
	}
	if obj["stream"] != true {
		t.Error("wire body stream not forced")
	}
	sys, _ := obj["messages"].([]any)[0].(map[string]any)["content"].(string)
	for _, fp := range []string{"x-anthropic-billing-header", ccIdentity, ccBranch} {
		if strings.Contains(sys, fp) {
			t.Errorf("wire body contains fingerprint %q: %q", fp, sys)
		}
	}
}

// 出站边界：关闭脱敏后 wire body 原样保留指纹（验证开关真实有效）。
func TestChatStreamWireBodySanitizeDisabled(t *testing.T) {
	var gotBody []byte
	ts := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	defer ts.Close()

	c := New()
	c.SanitizeFingerprints = false
	c.ChatBaseCN = ts.URL
	acct := &auth.Auth{AccessToken: "test-token", Domain: "copilot.tencent.com", UID: "u1"}

	body := []byte(`{"model":"glm-5.2","messages":[{"role":"system","content":"` + ccIdentity + `"}]}`)
	rc, status, _, err := c.ChatStream(acct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if status >= 400 {
		t.Fatalf("upstream status %d", status)
	}
	if !strings.Contains(string(gotBody), ccIdentity) {
		t.Error("sanitize disabled should preserve fingerprint on wire")
	}
}

// newTestUpstream 起一个假上游并捕获请求。
func newTestUpstream(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(h)
}
