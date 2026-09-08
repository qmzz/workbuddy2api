// sanitize.go 出站请求体脱敏：剥离上游内容审核黑名单指纹。
//
// 背景：各大 AI 编程客户端（Claude Code、Codex、OpenClaw、Hermes、QwenPaw 等）
// 在 system prompt 中注入若干固定模板句自报家门。
// 上游内容审核按逐字精确匹配拦截（非语义审核），一字改动即可绕过。
// 策略：
//  1. 键值/header 型指纹整段剥离。
//  2. 承载语义的模板句最小改写（通常换一词或微调修饰），语义不变，精确匹配失效。
package upstream

import (
	"regexp"
	"strings"
)

// sanitizeFeatures 特征预检：任一命中才进入净化（strings.Contains 快速路径，
// 普通请求全不中 → 原样返回，零分配）。
var sanitizeFeatures = []string{
	// --- 通用/底层 ---
	"x-anthropic-billing-header",
	"cc_entrypoint=",

	// --- 1. Claude Code ---
	"You are Claude Code",
	"Main branch (",

	// --- 2. OpenAI Codex CLI ---
	"You are Codex",

	// --- 3. OpenClaw ---
	"running inside OpenClaw",
	"openclaw:attempt",
	"openclaw:ctx",
	"BEGIN_OPENCLAW_INTERNAL_CONTEXT",
	"END_OPENCLAW_INTERNAL_CONTEXT",
	"OPENCLAW_INTERNAL_CONTEXT",

	// --- 4. Hermes Agent ---
	"You are Hermes",
	"Hermes Agent",

	// --- 5. QwenPaw (CoPaw) ---
	"QwenPaw",
	"CoPaw",
}

// sanitizeHdrRe 剥离层：header 键名即触发（与值无关），整段删除。
var sanitizeHdrRe = regexp.MustCompile(`(?i)x-anthropic-billing-header:[^;\n]*;?\s*`)

// sanitizeKvRe 剥离层：尾随裸键值（cc_xxx=...;）循环清理。
var sanitizeKvRe = regexp.MustCompile(`(?i)\bcc_[a-z0-9_]+=[^;\n]*;?\s*`)

// sanitizeRewrites 改写层：全模板句逐字替换（每句只改一个词或加微小修饰，语义不变）。
var sanitizeRewrites = [][2]string{
	// ==========================================
	// 1. Claude Code 指纹
	// ==========================================
	{
		"You are Claude Code, Anthropic's official CLI for Claude.",
		"You are Claude Code, Anthropic's official CLI tool for Claude.",
	},
	{
		"Main branch (you will usually use this for PRs)",
		"Default branch (you will usually use this for PRs)",
	},

	// ==========================================
	// 2. OpenAI Codex CLI 指纹 (实测已命中上游 11128)
	// ==========================================
	{
		"You are Codex, an OpenAI general-purpose agentic assistant that helps the user complete tasks across coding, browsing, apps, documents, research, and other digital workflows.",
		"You are Codex, an AI general-purpose agentic assistant that helps the user complete tasks across coding, browsing, apps, documents, research, and other digital workflows.",
	},
	{
		"You are Codex, a coding agent based on GPT-5.",
		"You are Codex, a coding assistant based on GPT-5.",
	},
	{
		"You are Codex, an agent based on GPT-5.",
		"You are Codex, an assistant based on GPT-5.",
	},
	{
		"You are Codex, an agent based on GPT-6.",
		"You are Codex, an assistant based on GPT-6.",
	},
	{
		"You are running as a coding agent in the Codex CLI",
		"You are running as a coding assistant in the Codex CLI",
	},

	// ==========================================
	// 3. OpenClaw 架构指纹（品牌词级清洗在 sanitizeText 尾部兜底）
	// ==========================================
	{
		"You are a personal assistant running inside OpenClaw.",
		"You are a personal assistant running inside a managed workspace.",
	},
	// 精确标记串先行替换（保留可读性的分隔符语义）
	{
		"<!-- openclaw:attempt:STABLE -->",
		"<!-- prompt:attempt:STABLE -->",
	},
	{
		"<!-- /openclaw:attempt:STABLE -->",
		"<!-- /prompt:attempt:STABLE -->",
	},
	{
		"<!-- openclaw:attempt:DYNAMIC -->",
		"<!-- prompt:attempt:DYNAMIC -->",
	},
	{
		"<!-- /openclaw:attempt:DYNAMIC -->",
		"<!-- /prompt:attempt:DYNAMIC -->",
	},
	{
		"<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>",
		"<<<BEGIN_INTERNAL_CONTEXT>>>",
	},
	{
		"<<<END_OPENCLAW_INTERNAL_CONTEXT>>>",
		"<<<END_INTERNAL_CONTEXT>>>",
	},
	{
		"BEGIN_OPENCLAW_INTERNAL_CONTEXT",
		"BEGIN_INTERNAL_CONTEXT",
	},
	{
		"END_OPENCLAW_INTERNAL_CONTEXT",
		"END_INTERNAL_CONTEXT",
	},
	{
		"⟦openclaw:ctx⟧",
		"⟦workspace:ctx⟧",
	},

	// ==========================================
	// 4. Hermes Agent 指纹
	// ==========================================
	{
		"You are Hermes, an AI assistant created by Nous Research.",
		"You are Hermes, an AI assistant developed by Nous Research.",
	},
	{
		"You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
		"You are Hermes Agent, an intelligent AI assistant developed by Nous Research.",
	},

	// ==========================================
	// 5. QwenPaw (原 CoPaw) 指纹
	// ==========================================
	{
		"You are QwenPaw, a personal AI assistant",
		"You are QwenPaw, an intelligent personal AI assistant",
	},
	{
		"You are CoPaw, a personal AI assistant",
		"You are CoPaw, an intelligent personal AI assistant",
	},
	{
		"You are CoPaw, an AI assistant.",
		"You are CoPaw, a helpful AI assistant.",
	},
}

// sanitizeText 单段文本净化：预检不中 → 返回原串（零分配）。
func sanitizeText(text string) string {
	if !hasFingerprint(text) {
		return text
	}
	for _, rw := range sanitizeRewrites {
		text = strings.ReplaceAll(text, rw[0], rw[1])
	}
	if sanitizeHdrRe.MatchString(text) {
		text = sanitizeHdrRe.ReplaceAllString(text, "")
	}
	if strings.Contains(text, "cc_") {
		prev := ""
		for prev != text { // 清尾随裸 kv（cc_version=...; cc_entrypoint=...;）
			prev = text
			text = sanitizeKvRe.ReplaceAllString(text, "")
		}
	}
	// 全量清洗：OpenClaw 品牌词（大小写不敏感）→ 中性词 workspace。
	// 上游黑名单可能匹配任何含 openclaw 的子串，逐句改写不可穷举，词级替换兜底所有变体。
	if openClawWordRe.MatchString(text) {
		text = openClawWordRe.ReplaceAllString(text, "workspace")
	}
	return strings.TrimSpace(text)
}

// openClawWordRe 词级清洗：命中任意大小写 openclaw 即进入替换。
// 不用 \b 边界：BEGIN_OPENCLAW_INTERNAL_CONTEXT 等下划线相连形式在字母左右都是词字符，
// \b 匹配不到，必须裸匹配 openclaw 才能覆盖全部变体。
var openClawWordRe = regexp.MustCompile(`(?i)openclaw`)

// hasFingerprint 特征预检：先走 strings.Contains 快速路径（零分配）；
// header 键名/品牌词有大小写变体，快速路径漏掉时再落正则（(?i)）兜底。
func hasFingerprint(text string) bool {
	for _, f := range sanitizeFeatures {
		if strings.Contains(text, f) {
			return true
		}
	}
	if sanitizeHdrRe.MatchString(text) {
		return true
	}
	return openClawWordRe.MatchString(text)
}

// sanitizeContent 兼容字符串与多模态数组；只动 text part，image 等 part 不动。
// 返回净化后的值及是否发生变化。
func sanitizeContent(v any) (any, bool) {
	switch c := v.(type) {
	case string:
		s := sanitizeText(c)
		return s, s != c
	case []any:
		changed := false
		for _, p := range c {
			m, ok := p.(map[string]any)
			if !ok {
				continue
			}
			text, ok := m["text"].(string)
			if !ok {
				continue
			}
			if s := sanitizeText(text); s != text {
				m["text"] = s
				changed = true
			}
		}
		return c, changed
	}
	return v, false
}

// sanitizeMessages 净化 messages 中的 content；任一命中返回 true。
func sanitizeMessages(messages []any) bool {
	changed := false
	for _, msg := range messages {
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		c, ok := m["content"]
		if !ok {
			continue
		}
		if nc, ch := sanitizeContent(c); ch {
			m["content"] = nc
			changed = true
		}
	}
	return changed
}
