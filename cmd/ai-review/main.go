package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	githubAPI = "https://api.github.com"
	openaiAPI = "https://api.openai.com/v1/responses"
)

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing env: %s\n", key)
		os.Exit(1)
	}
	return v
}

func envDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func httpDo(client *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return b, resp.StatusCode, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, resp.StatusCode, nil
}

func redactSecrets(s string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (?:RSA|EC|PRIVATE) KEY-----[\s\S]*?-----END (?:RSA|EC|PRIVATE) KEY-----`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS access key
		regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"][^'"\n]{8,}['"]`),
		regexp.MustCompile(`(?i)authorization:\s*bearer\s+[a-z0-9\-\._~\+\/]+=*`),
	}
	out := s
	for _, re := range patterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

// ---------------- GitHub: fetch PR diff ----------------
func fetchPRDiff(client *http.Client, repo string, prNumber int, githubToken string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/pulls/%d", githubAPI, repo, prNumber)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3.diff")

	b, _, err := httpDo(client, req)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------------- GitHub: fetch PR head sha ----------------
type prInfoResp struct {
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func fetchPRHeadSHA(client *http.Client, repo string, prNumber int, githubToken string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/pulls/%d", githubAPI, repo, prNumber)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	b, _, err := httpDo(client, req)
	if err != nil {
		return "", err
	}

	var pr prInfoResp
	if err := json.Unmarshal(b, &pr); err != nil {
		return "", err
	}
	if strings.TrimSpace(pr.Head.SHA) == "" {
		return "", fmt.Errorf("missing head sha")
	}
	return pr.Head.SHA, nil
}

// ---------------- GitHub: post summary (fallback) ----------------
func postPRComment(client *http.Client, repo string, prNumber int, githubToken, body string) error {
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments", githubAPI, repo, prNumber)
	payload := map[string]string{"body": body}
	j, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	_, _, err := httpDo(client, req)
	return err
}

// ---------------- GitHub: inline comment ----------------
type inlineCommentReq struct {
	Body     string `json:"body"`
	CommitID string `json:"commit_id"`
	Path     string `json:"path"`
	Side     string `json:"side"` // "RIGHT" or "LEFT"
	Line     int    `json:"line"`
	// Optional:
	StartSide string `json:"start_side,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
}

func postInlineComment(client *http.Client, repo string, prNumber int, githubToken string, reqBody inlineCommentReq) error {
	url := fmt.Sprintf("%s/repos/%s/pulls/%d/comments", githubAPI, repo, prNumber)

	j, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	_, _, err := httpDo(client, req)
	return err
}

// -------- OpenAI Responses API types (minimal) --------
type responsesReq struct {
	Model string      `json:"model"`
	Input []inputItem `json:"input"`
}

type inputItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responsesResp struct {
	Output []struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
}

// -------- GPT structured review --------
type GPTReview struct {
	Summary  []string `json:"summary"`
	Findings []struct {
		Severity   string `json:"severity"` // HIGH|MEDIUM|LOW
		Path       string `json:"path"`
		Side       string `json:"side"` // RIGHT|LEFT
		Line       int    `json:"line"`
		Title      string `json:"title"`
		Detail     string `json:"detail"`
		Suggestion string `json:"suggestion"`
		Patch      string `json:"patch"`
	} `json:"findings"`
	SuggestedTests []string `json:"suggested_tests"`
}

func normalizeSide(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s != "LEFT" && s != "RIGHT" {
		return "RIGHT"
	}
	return s
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "HIGH", "MEDIUM", "LOW":
		return s
	default:
		return "LOW"
	}
}

func renderInlineBody(sev, title, detail, suggestion, patch string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("**%s** — %s\n\n", sev, title))
	if strings.TrimSpace(detail) != "" {
		b.WriteString(detail)
		b.WriteString("\n\n")
	}
	if strings.TrimSpace(suggestion) != "" {
		b.WriteString("✅ **Suggestion:** ")
		b.WriteString(suggestion)
		b.WriteString("\n")
	}
	if strings.TrimSpace(patch) != "" {
		patch = strings.TrimSpace(patch)
		b.WriteString("\n<details>\n<summary>Proposed patch</summary>\n\n```diff\n")
		// keep patch small-ish
		lines := strings.Split(patch, "\n")
		if len(lines) > 25 {
			lines = lines[:25]
			lines = append(lines, "... (truncated)")
		}
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n```\n</details>\n")
	}
	return b.String()
}

func renderSummaryComment(model string, r GPTReview, inlinePosted, inlineFailed int) string {
	var b strings.Builder
	b.WriteString("## 🤖 AI Review (GPT)\n\n")
	b.WriteString(fmt.Sprintf("_Model_: `%s`\n\n", model))

	if len(r.Summary) > 0 {
		b.WriteString("### Summary\n")
		for _, s := range r.Summary {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			b.WriteString("- ")
			b.WriteString(s)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("### Inline comments\n")
	b.WriteString(fmt.Sprintf("- Posted: **%d**\n", inlinePosted))
	b.WriteString(fmt.Sprintf("- Failed (fallback to summary): **%d**\n\n", inlineFailed))

	if len(r.SuggestedTests) > 0 {
		b.WriteString("### Suggested tests\n")
		for _, t := range r.SuggestedTests {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			b.WriteString("- ")
			b.WriteString(t)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// If some findings couldn't be posted inline, list them here
	if inlineFailed > 0 && len(r.Findings) > 0 {
		b.WriteString("### Findings (fallback list)\n")
		for _, f := range r.Findings {
			sev := normalizeSeverity(f.Severity)
			path := strings.TrimSpace(f.Path)
			line := f.Line
			title := strings.TrimSpace(f.Title)
			if path == "" || line <= 0 || title == "" {
				continue
			}
			b.WriteString(fmt.Sprintf("- **%s** `%s:%d` — %s\n", sev, path, line, title))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func callGPTStructured(client *http.Client, apiKey, model, diff string) (GPTReview, error) {
	// Go-backend specialized prompt, strict JSON output
	prompt := fmt.Sprintf(`
You are a senior Go backend reviewer. Review ONLY the provided Git diff.

Primary goals (in order):
1) Correctness & reliability (panic, nil, race, data corruption, idempotency)
2) Security (secrets, injection, authn/authz, SSRF, unsafe crypto)
3) Performance (allocations, hot paths, N+1, IO, retries)
4) Maintainability (clean interfaces, error handling, naming, tests)

Go-specific checklist:
- context.Context: propagated? cancellation respected? timeouts?
- concurrency: goroutine leak, channel blocking, race, sync usage
- error handling: wrap errors, sentinel errors, returning useful context
- logging/observability: avoid PII, include request/trace IDs, structured logs
- HTTP clients: timeouts, retry/backoff, status code handling
- database: transactions boundaries, N+1 patterns, indexes, query limits
- security: never log tokens/keys; validate inputs; avoid trusting headers blindly
- testing: suggest unit/integration tests for changed logic

Output STRICT JSON (no markdown, no extra text):
{
  "summary": ["..."],
  "findings": [
    {
      "severity": "HIGH|MEDIUM|LOW",
      "path": "<file path from diff>",
      "side": "RIGHT|LEFT",
      "line": <integer line number on that side>,
      "title": "<short>",
      "detail": "<why it matters>",
      "suggestion": "<actionable fix>",
      "patch": "<optional small code snippet or unified diff, max 20 lines>"
    }
  ],
  "suggested_tests": ["..."]
}

Rules:
- Only include findings grounded in the diff.
- If you are unsure about exact line number, OMIT that finding.
- Limit findings to max 10.

DIFF:
%s
`, diff)

	reqBody := responsesReq{
		Model: model,
		Input: []inputItem{
			{Role: "user", Content: strings.TrimSpace(prompt)},
		},
	}
	j, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, openaiAPI, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	b, _, err := httpDo(client, req)
	if err != nil {
		return GPTReview{}, err
	}

	var rr responsesResp
	if err := json.Unmarshal(b, &rr); err != nil {
		return GPTReview{}, err
	}

	var out []string
	for _, o := range rr.Output {
		for _, c := range o.Content {
			if c.Type == "output_text" && strings.TrimSpace(c.Text) != "" {
				out = append(out, c.Text)
			}
		}
	}
	raw := strings.TrimSpace(strings.Join(out, "\n"))
	if raw == "" {
		return GPTReview{}, fmt.Errorf("empty model output")
	}

	// Attempt to parse JSON. Sometimes model may wrap with whitespace; we keep it strict.
	var gr GPTReview
	if err := json.Unmarshal([]byte(raw), &gr); err != nil {
		// If parse fails, include raw in error for debugging (careful: could be large)
		return GPTReview{}, fmt.Errorf("failed to parse JSON output: %v; raw=%s", err, truncate(raw, 1200))
	}

	// Normalize some fields defensively
	for i := range gr.Findings {
		gr.Findings[i].Severity = normalizeSeverity(gr.Findings[i].Severity)
		gr.Findings[i].Side = normalizeSide(gr.Findings[i].Side)
	}

	return gr, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

func main() {
	githubToken := mustEnv("GITHUB_TOKEN")
	openaiKey := mustEnv("OPENAI_API_KEY")
	model := envDefault("OPENAI_MODEL", "gpt-4.1-mini")
	repo := mustEnv("REPO")

	prStr := mustEnv("PR_NUMBER")
	prNumber, err := strconv.Atoi(prStr)
	if err != nil || prNumber <= 0 {
		fmt.Fprintf(os.Stderr, "invalid PR_NUMBER: %s\n", prStr)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	// 1) Get PR head SHA (needed for inline comment API)
	headSHA, err := fetchPRHeadSHA(client, repo, prNumber, githubToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch head sha error: %v\n", err)
		os.Exit(1)
	}

	// 2) Fetch diff
	diff, err := fetchPRDiff(client, repo, prNumber, githubToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch diff error: %v\n", err)
		os.Exit(1)
	}

	diff = redactSecrets(diff)

	// Demo limit: avoid huge diffs (cost + token)
	const maxChars = 60_000
	if len(diff) > maxChars {
		diff = diff[:maxChars] + "\n\n... (diff truncated)"
	}

	// 3) Ask GPT for structured review
	review, err := callGPTStructured(client, openaiKey, model, diff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpt error: %v\n", err)
		os.Exit(1)
	}

	// 4) Post inline comments (best effort)
	inlinePosted := 0
	inlineFailed := 0

	// limit inline comments (avoid spam)
	const maxInline = 8
	count := 0

	for _, f := range review.Findings {
		if count >= maxInline {
			break
		}

		path := strings.TrimSpace(f.Path)
		line := f.Line
		title := strings.TrimSpace(f.Title)

		// Must have path + line + title for inline.
		if path == "" || line <= 0 || title == "" {
			continue
		}

		sev := normalizeSeverity(f.Severity)
		side := normalizeSide(f.Side)

		body := renderInlineBody(sev, title, f.Detail, f.Suggestion, f.Patch)

		reqBody := inlineCommentReq{
			Body:     body,
			CommitID: headSHA,
			Path:     path,
			Side:     side,
			Line:     line,
		}

		if err := postInlineComment(client, repo, prNumber, githubToken, reqBody); err != nil {
			// Common case: 422 if line/path not valid in this commit context.
			inlineFailed++
			continue
		}

		inlinePosted++
		count++
	}

	// 5) Always post a summary comment (so PR has a single place to read)
	summary := renderSummaryComment(model, review, inlinePosted, inlineFailed)
	if err := postPRComment(client, repo, prNumber, githubToken, summary); err != nil {
		fmt.Fprintf(os.Stderr, "post summary comment error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("posted summary. inline posted=%d failed=%d\n", inlinePosted, inlineFailed)
}
