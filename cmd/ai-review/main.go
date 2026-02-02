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

func callGPT(client *http.Client, apiKey, model, diff string) (string, error) {
	prompt := fmt.Sprintf(`
You are a senior code reviewer. Review the following Git diff of a GitHub Pull Request.

Rules:
- Focus on correctness, security, performance, and maintainability.
- Be specific: refer to files and diff hunks.
- Provide actionable suggestions and small code snippets when helpful.
- If you see secrets/keys, warn and suggest removal (some may be redacted).
- Keep it concise.

Return Markdown with:
1) Summary (bullet points)
2) Findings by severity: HIGH / MEDIUM / LOW
3) Suggested tests (if any)

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
		return "", err
	}

	var rr responsesResp
	if err := json.Unmarshal(b, &rr); err != nil {
		return "", err
	}

	var out []string
	for _, o := range rr.Output {
		for _, c := range o.Content {
			if c.Type == "output_text" && strings.TrimSpace(c.Text) != "" {
				out = append(out, c.Text)
			}
		}
	}
	if len(out) == 0 {
		return "(No output)", nil
	}
	return strings.Join(out, "\n"), nil
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

	diff, err := fetchPRDiff(client, repo, prNumber, githubToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch diff error: %v\n", err)
		os.Exit(1)
	}

	diff = redactSecrets(diff)

	// Demo limit: tránh diff quá to
	const maxChars = 60_000
	if len(diff) > maxChars {
		diff = diff[:maxChars] + "\n\n... (diff truncated)"
	}

	review, err := callGPT(client, openaiKey, model, diff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpt error: %v\n", err)
		os.Exit(1)
	}

	comment := fmt.Sprintf("## 🤖 AI Review (GPT)\n\n_Model_: `%s`\n\n%s\n", model, review)

	if err := postPRComment(client, repo, prNumber, githubToken, comment); err != nil {
		fmt.Fprintf(os.Stderr, "post comment error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("posted AI review comment successfully")
}
