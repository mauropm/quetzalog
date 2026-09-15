package entities

import "testing"

func TestNormalizeUser(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantAl  int
	}{
		{"DOMAIN\\Mauro", "mauro", 1},
		{"domain/mauro", "mauro", 1},
		{"Mauro", "mauro", 0},
		{`CORP\svc_backup`, "svc_backup", 1},
	}
	for _, c := range cases {
		got, aliases := NormalizeUser(c.in)
		if got != c.want {
			t.Errorf("NormalizeUser(%q) = %q want %q", c.in, got, c.want)
		}
		if len(aliases) != c.wantAl {
			t.Errorf("NormalizeUser(%q) aliases = %v (want %d)", c.in, aliases, c.wantAl)
		}
	}
}

func TestNormalizeHostDomain(t *testing.T) {
	if got := NormalizeHost("web-01.prod"); got != "WEB-01.PROD" {
		t.Errorf("host: %q", got)
	}
	if got := NormalizeDomain("Corp.Example.com:8443/"); got != "corp.example.com" {
		t.Errorf("domain w/ port: %q", got)
	}
	if got := NormalizeDomain("EXAMPLE.COM."); got != "example.com" {
		t.Errorf("domain trailing dot: %q", got)
	}
}

func TestNormalizeURL(t *testing.T) {
	if got := NormalizeURL("HTTPS://Api.Example.com/Path/x"); got != "https://api.example.com/Path/x" {
		t.Errorf("url: %q", got)
	}
	if got := NormalizeURL("http://h:8080"); got != "http://h:8080" {
		t.Errorf("url port: %q", got)
	}
	if got := NormalizeURL("not a url"); got != "not a url" {
		t.Errorf("url passthrough: %q", got)
	}
}

func TestNormalizeProcess(t *testing.T) {
	if got, al := NormalizeProcess("/usr/bin/evil"); got != "evil" || len(al) != 1 {
		t.Errorf("posix process: %q %v", got, al)
	}
	if got, al := NormalizeProcess(`C:\tools\evil.exe`); got != "evil.exe" || len(al) != 1 {
		t.Errorf("windows process: %q %v", got, al)
	}
	if got, _ := NormalizeProcess("bash"); got != "bash" {
		t.Errorf("bare process: %q", got)
	}
}

func TestNormalizeHash(t *testing.T) {
	if got := NormalizeHash("ABCDEF0123456789ABCDEF0123456789"); got != "abcdef0123456789abcdef0123456789" {
		t.Errorf("md5 lowercase: %q", got)
	}
	if got := NormalizeHash("not-a-hash"); got != "" {
		t.Errorf("non-hash accepted: %q", got)
	}
	if got := NormalizeHash("abc"); got != "" {
		t.Errorf("short value accepted: %q", got)
	}
}

func TestExtractFromAttributes(t *testing.T) {
	out := ExtractFromAttributes(map[string]any{
		"domain":      "CORP.example.com",
		"url":         "https://api.example.com/admin",
		"email":       "Admin@Corp.com",
		"file_hash":   "ABCDEF0123456789ABCDEF0123456789",
		"file":        "/var/tmp/drop",
		"process":     `/opt/bin/agent`,
		"user":        `DOM\Jane`,
		"unrelated":   42,
	})
	byType := map[string]Extracted{}
	for _, e := range out {
		byType[e.Type] = e
	}
	if byType[TypeDomain].Value != "corp.example.com" {
		t.Errorf("domain: %q", byType[TypeDomain].Value)
	}
	if byType[TypeURL].Value != "https://api.example.com/admin" {
		t.Errorf("url: %q", byType[TypeURL].Value)
	}
	if byType[TypeEmail].Value != "admin@corp.com" {
		t.Errorf("email: %q", byType[TypeEmail].Value)
	}
	if byType[TypeHash].Value != "abcdef0123456789abcdef0123456789" {
		t.Errorf("hash: %q", byType[TypeHash].Value)
	}
	if byType[TypeProcess].Value != "agent" || len(byType[TypeProcess].Aliases) != 1 {
		t.Errorf("process: %+v", byType[TypeProcess])
	}
	if byType[TypeUser].Value != "jane" || len(byType[TypeUser].Aliases) != 1 {
		t.Errorf("user: %+v", byType[TypeUser])
	}
	if len(byType) != 7 {
		t.Errorf("extraction count: %d (%+v)", len(byType), byType)
	}
}

func TestIsBlockedOutcome(t *testing.T) {
	for _, o := range []string{"deny", "DENIED", "blocked", "failed", "failure"} {
		if !isBlockedOutcome(o) {
			t.Errorf("%q not recognized as blocked", o)
		}
	}
	for _, o := range []string{"success", "ok", ""} {
		if isBlockedOutcome(o) {
			t.Errorf("%q wrongly blocked", o)
		}
	}
}
