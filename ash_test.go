package main

import (
	"testing"
)

func TestExtractLinks(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"no links", "hello world", nil},
		{"single http", "check http://example.com out", []string{"http://example.com"}},
		{"single https", "visit https://example.com/page", []string{"https://example.com/page"}},
		{"multiple links", "see https://a.com and http://b.com/path",
			[]string{"https://a.com", "http://b.com/path"}},
		{"link with query", "go to https://example.com/search?q=test&page=1",
			[]string{"https://example.com/search?q=test&page=1"}},
		{"case insensitive", "HTTPS://EXAMPLE.COM", []string{"HTTPS://EXAMPLE.COM"}},
		{"empty string", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractLinks(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractLinks(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ExtractLinks(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsBlacklisted(t *testing.T) {
	blacklist, err := LoadBlacklist("blacklist.json")
	if err != nil {
		t.Skipf("skipping blacklist test (no blacklist.json): %v", err)
	}
	// Just verify it doesn't crash with a normal URL
	_ = IsBlacklisted("https://example.com", blacklist)
}

func TestExtractJSONPath(t *testing.T) {
	root := map[string]interface{}{
		"a": map[string]interface{}{
			"b": "value",
			"c": 42.0,
		},
		"top": "hello",
	}
	tests := []struct {
		path string
		want interface{}
	}{
		{"", root},
		{"top", "hello"},
		{"a.b", "value"},
		{"a.c", 42.0},
		{"missing", nil},
		{"a.missing", nil},
		{"a.b.deep", nil},
	}
	for _, tt := range tests {
		t.Run("path="+tt.path, func(t *testing.T) {
			got := extractJSONPath(root, tt.path)
			if tt.want == nil && got != nil {
				t.Errorf("extractJSONPath(_, %q) = %v, want nil", tt.path, got)
			} else if tt.want != nil {
				if s, ok := tt.want.(string); ok {
					if gs, ok := got.(string); !ok || gs != s {
						t.Errorf("extractJSONPath(_, %q) = %v, want %q", tt.path, got, s)
					}
				}
			}
		})
	}
}

func TestFormatPosts(t *testing.T) {
	posts := []interface{}{
		map[string]interface{}{"title": "Post 1", "url": "https://a.com"},
		map[string]interface{}{"title": "Post 2", "url": "https://b.com"},
	}
	result := formatPosts(posts, "https://linkstash.example.com")
	if result == "" {
		t.Error("formatPosts returned empty string")
	}
	if !contains(result, "Post 1") || !contains(result, "Post 2") {
		t.Errorf("formatPosts missing post titles: %s", result)
	}
	if !contains(result, "https://linkstash.example.com") {
		t.Errorf("formatPosts missing linkstash URL: %s", result)
	}
}

func TestFormatPostsLimit(t *testing.T) {
	// More than 5 posts should be capped
	posts := make([]interface{}, 10)
	for i := range posts {
		posts[i] = map[string]interface{}{
			"title": "Post",
			"url":   "https://example.com",
		}
	}
	result := formatPosts(posts, "https://linkstash.example.com")
	// Count lines with "- " prefix (capped at 5)
	lines := 0
	for _, line := range splitLines(result) {
		if len(line) > 0 && line[0] == '-' {
			lines++
		}
	}
	if lines != 5 {
		t.Errorf("formatPosts should cap at 5 posts, got %d", lines)
	}
}

func TestTruncateText(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		tokenLimit int
		wantMax    int // max chars in result
	}{
		{"short text", "hello", 100, 5},
		{"at limit", "hello world", 100, 11},
		{"over limit", string(make([]byte, 10000)), 10, 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateText(tt.text, tt.tokenLimit)
			if len(got) > tt.wantMax+10 { // small buffer for boundary rounding
				t.Errorf("truncateText len = %d, want <= %d", len(got), tt.wantMax)
			}
		})
	}
}

func TestStripCommandPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/bot gork what is life", "what is life"},
		{"/bot gork", ""},
		{"@gork hello world", "hello world"},
		{"@gork: explain this", "explain this"},
		{"plain text", "plain text"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripCommandPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripCommandPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveReplyLabel(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *Config
		botCfg *BotConfig
		want   string
	}{
		{"both nil", nil, nil, "> "},
		{"config label", &Config{BotReplyLabel: "[bot] "}, nil, "[bot] "},
		{"bot config label", &Config{}, &BotConfig{Label: "🤖 "}, "🤖 "},
		{"config takes precedence", &Config{BotReplyLabel: "[bot] "}, &BotConfig{Label: "🤖 "}, "[bot] "},
		{"empty config, empty bot", &Config{}, &BotConfig{}, "> "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveReplyLabel(tt.cfg, tt.botCfg)
			if got != tt.want {
				t.Errorf("resolveReplyLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInSlice(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !inSlice(slice, "b") {
		t.Error("inSlice should find 'b'")
	}
	if inSlice(slice, "d") {
		t.Error("inSlice should not find 'd'")
	}
	if inSlice(nil, "a") {
		t.Error("inSlice should return false for nil slice")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("hello", 10) != "hello" {
		t.Error("truncate should not truncate short string")
	}
	got := truncate("hello world", 5)
	if got != "hello..." {
		t.Errorf("truncate = %q, want %q", got, "hello...")
	}
}

func TestGenerateHelpMessage(t *testing.T) {
	botCfg := &BotConfig{
		Commands: map[string]BotCommand{
			"hello":   {Type: "http"},
			"deepfry": {Type: "exec"},
			"gork":    {Type: "ai"},
		},
	}

	// No filter
	msg := generateHelpMessage(botCfg, nil)
	if !contains(msg, "deepfry") || !contains(msg, "gork") || !contains(msg, "hello") {
		t.Errorf("generateHelpMessage missing commands: %s", msg)
	}

	// With filter
	msg = generateHelpMessage(botCfg, []string{"hello", "gork"})
	if !contains(msg, "hello") || !contains(msg, "gork") {
		t.Errorf("generateHelpMessage with filter missing commands: %s", msg)
	}
	if contains(msg, "deepfry") {
		t.Errorf("generateHelpMessage should not include filtered-out command: %s", msg)
	}
}

func TestLoadBotConfig(t *testing.T) {
	cfg, err := LoadBotConfig("bot.json")
	if err != nil {
		t.Skipf("skipping (no bot.json): %v", err)
	}
	if cfg.Commands == nil {
		t.Fatal("Commands map is nil")
	}
	// Verify required commands exist
	for _, name := range []string{"hi", "summary", "gork"} {
		if _, ok := cfg.Commands[name]; !ok {
			t.Errorf("required command %q not found", name)
		}
	}
	// Verify each command has a valid type or static response
	for name, cmd := range cfg.Commands {
		if cmd.Response != "" {
			continue
		}
		switch cmd.Type {
		case "http", "exec", "ai":
		default:
			t.Errorf("command %q has invalid type %q", name, cmd.Type)
		}
	}
}

// helpers

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
