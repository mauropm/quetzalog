package ai

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		in      string
		contains []string
	}{
		{
			in:       "login failed for admin password=hunter2secret on host",
			contains: []string{"[REDACTED:password]"},
		},
		{
			in:       `api_key: sk-live-abcdef1234567890 sent`,
			contains: []string{"[REDACTED:token]"},
		},
		{
			in:       "Authorization: Bearer abcdef1234567890XYZW",
			contains: []string{"[REDACTED:token]"},
		},
		{
			in:       "cloud creds AKIA1234567890ABCDEF in payload",
			contains: []string{"[REDACTED:token]"},
		},
		{
			in:       "Set-Cookie: sessionid=abc123def456; Path=/",
			contains: []string{"[REDACTED:cookie]"},
		},
		{
			in:       "user 123-45-6789 registered",
			contains: []string{"[REDACTED:ssn]"},
		},
	}
	for _, c := range cases {
		out, fired := RedactText(c.in)
		for _, want := range c.contains {
			if !strings.Contains(out, want) {
				t.Errorf("RedactText(%q) = %q, want containing %q", c.in, out, want)
			}
		}
		if len(fired) == 0 {
			t.Errorf("RedactText(%q) reported no categories", c.in)
		}
		// Deterministic.
		out2, _ := RedactText(c.in)
		if out != out2 {
			t.Errorf("RedactText not deterministic: %q vs %q", out, out2)
		}
	}
}

func TestRedactLeavesCleanText(t *testing.T) {
	clean := "user admin logged in from 10.0.0.5 to host web-01"
	out, fired := RedactText(clean)
	if out != clean {
		t.Errorf("clean text modified: %q", out)
	}
	if len(fired) != 0 {
		t.Errorf("clean text flagged: %v", fired)
	}
}

func TestRedactSHAHashNotFlagged(t *testing.T) {
	// Security indicators (hashes) must not be redacted as token material.
	h := "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	out, _ := RedactText(h)
	if strings.Contains(out, "[REDACTED") {
		t.Errorf("sha256 hash redacted: %q", out)
	}
}
