package parsers

import (
	"testing"
	"time"

	"quetzalog/pkg/event"
)

func TestCEFParse(t *testing.T) {
	line := `CEF:8|Quetzalog|TestFW|1.0|100|Blocked inbound connection|7|src=10.1.2.3 dst=203.0.113.9 dpt=445 rt=2026-01-02T03:04:05Z suser=alice msg=connection \| blocked by policy cn1=42`
	p, ok := (cefParser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("cef did not match")
	}
	if p.Message != "Blocked inbound connection" {
		t.Errorf("message: %q", p.Message)
	}
	if p.Severity != "err" {
		t.Errorf("severity: %q (want err from cef 7)", p.Severity)
	}
	if p.SourceIP != "10.1.2.3" || p.DestIP != "203.0.113.9" || p.DestPort != 445 {
		t.Errorf("ips/ports: %q %q %d", p.SourceIP, p.DestIP, p.DestPort)
	}
	if p.User != "alice" {
		t.Errorf("user: %q", p.User)
	}
	if !p.Timestamp.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("timestamp: %v", p.Timestamp)
	}
	if p.Attributes["msg"] != "connection | blocked by policy" {
		t.Errorf("escaped pipe: %q", p.Attributes["msg"])
	}
	if p.Attributes["cn1"] != "42" {
		t.Errorf("cn1: %q", p.Attributes["cn1"])
	}
	if p.Attributes["cef.version"] != "8" || p.Attributes["cef.signature_id"] != "100" {
		t.Errorf("header attrs: %v", p.Attributes)
	}
	if p.Attributes["src"] != nil {
		t.Error("known fields must not leak into attributes")
	}
}

func TestCEFNoMatch(t *testing.T) {
	if _, ok := (cefParser{}).Parse([]byte("CEF missing")); ok {
		t.Error("non-CEF line matched")
	}
	if _, ok := (cefParser{}).Parse([]byte("CEF:8|only|two|fields")); ok {
		t.Error("short CEF header matched")
	}
}

func TestCEFSeverityMapping(t *testing.T) {
	cases := map[int]string{
		0: "debug", 1: "notice", 3: "notice", 4: "warning",
		5: "warning", 6: "err", 7: "err", 8: "critical", 10: "critical",
	}
	for in, want := range cases {
		if got := cefSeverity(in); got != want {
			t.Errorf("cefSeverity(%d) = %q want %q", in, got, want)
		}
	}
}

func TestLEEFParse(t *testing.T) {
	line := `LEEF:2.0 eventid=123!hostname=db01!username=bob!srcip=10.0.0.5!dstip=10.0.0.9!timestamp=1756900000!severity=high!msg=login ok!action=LOGIN`
	p, ok := (leefParser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("leef did not match")
	}
	if p.Host != "db01" || p.User != "bob" {
		t.Errorf("host/user: %q %q", p.Host, p.User)
	}
	if p.SourceIP != "10.0.0.5" || p.DestIP != "10.0.0.9" {
		t.Errorf("ips: %q %q", p.SourceIP, p.DestIP)
	}
	if p.Severity != "high" {
		t.Errorf("severity: %q", p.Severity)
	}
	if p.Message != "login ok" {
		t.Errorf("message: %q", p.Message)
	}
	if p.Attributes["eventid"] != "123" || p.Attributes["action"] != "LOGIN" {
		t.Errorf("attrs: %v", p.Attributes)
	}
	if p.Timestamp.IsZero() || p.Timestamp.Unix() != 1756900000 {
		t.Errorf("timestamp: %v", p.Timestamp)
	}
}

func TestLEEFEscaping(t *testing.T) {
	line := `LEEF:2.0 note=exclam\!ation!path=C\:\\tmp!eq=a\=b`
	p, ok := (leefParser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("leef did not match")
	}
	// In LEEF, "\!" is an escaped bang that stays in the value.
	if p.Attributes["note"] != "exclam!ation" {
		t.Errorf("escaped bang: %q", p.Attributes["note"])
	}
	if p.Attributes["path"] != `C:\tmp` {
		t.Errorf("escaped backslash: %q", p.Attributes["path"])
	}
	if p.Attributes["eq"] != "a=b" {
		t.Errorf("escaped equals: %q", p.Attributes["eq"])
	}
}

func TestGELFParse(t *testing.T) {
	line := `{"version":"1.1","host":"h1","short_message":"boom","full_message":"boom detailed","timestamp":1756900000.5,"_user":"carol","_db":"pg"}`
	p, ok := (gelfParser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("gelf did not match")
	}
	if p.Host != "h1" || p.Message != "boom" {
		t.Errorf("host/message: %q %q", p.Host, p.Message)
	}
	if p.Attributes["user"] != "carol" || p.Attributes["db"] != "pg" {
		t.Errorf("attrs: %v", p.Attributes)
	}
	if p.Timestamp.IsZero() {
		t.Error("timestamp not parsed")
	}
}

func TestGELFFullMessageOnly(t *testing.T) {
	line := `{"version":"1.1","full_message":"long text","host":"h2"}`
	p, ok := (gelfParser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("gelf did not match")
	}
	if p.Message != "long text" {
		t.Errorf("message: %q", p.Message)
	}
}

func TestGELFRejectsArbitraryJSON(t *testing.T) {
	if _, ok := (gelfParser{}).Parse([]byte(`{"a":1,"version":"2.0"}`)); ok {
		t.Error("non-gelf version matched")
	}
	if _, ok := (gelfParser{}).Parse([]byte(`{"version":"1.1","foo":"bar"}`)); ok {
		t.Error("json without gelf characteristic fields matched")
	}
	if _, ok := (gelfParser{}).Parse([]byte(`not json`)); ok {
		t.Error("non-json matched")
	}
}

func TestSyslog5424WithStructuredData(t *testing.T) {
	line := `<165>1 2026-01-01T00:00:00Z web01 nginx 728 ID47 <id@10 name="nginx" req="GET /"><auth method="tls"> user=alice message here`
	p, ok := (syslog5424Parser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("5424 did not match")
	}
	if p.Host != "web01" || p.Source != "nginx" || p.ProcessID != "728" {
		t.Errorf("host/source/pid: %q %q %q", p.Host, p.Source, p.ProcessID)
	}
	if p.Attributes["msgid"] != "ID47" {
		t.Errorf("msgid: %v", p.Attributes["msgid"])
	}
	if p.Attributes["sdid"] != "id@10" {
		t.Errorf("sdid: %v", p.Attributes)
	}
	if p.Attributes["sd.id@10.name"] != "nginx" || p.Attributes["sd.id@10.req"] != "GET /" {
		t.Errorf("sd params: %v", p.Attributes)
	}
	if p.Attributes["sd.auth.method"] != "tls" {
		t.Errorf("second sd element: %v", p.Attributes)
	}
	if p.Message != "user=alice message here" {
		t.Errorf("message: %q", p.Message)
	}
	if p.Severity != "notice" {
		t.Errorf("severity: %q (pri 165 = facility 20, sev 5)", p.Severity)
	}
}

func TestSyslog5424NoSD(t *testing.T) {
	line := `<165>1 2026-01-01T00:00:00Z web01 nginx - ID[728] - GET /admin returned 403`
	p, ok := (syslog5424Parser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("5424 did not match")
	}
	if p.Host != "web01" || p.Source != "nginx" {
		t.Errorf("host/source: %q %q", p.Host, p.Source)
	}
	if p.Message != "GET /admin returned 403" {
		t.Errorf("message: %q", p.Message)
	}
	if p.Attributes["sdid"] != nil {
		t.Errorf("unexpected sdid: %v", p.Attributes)
	}
}

func TestSyslog3164Parse(t *testing.T) {
	line := `<134>Sep  3 18:30:00 server01 sshd: Failed password for admin`
	p, ok := (syslog3164Parser{}).Parse([]byte(line))
	if !ok {
		t.Fatal("3164 did not match")
	}
	if p.Host != "server01" || p.Source != "sshd" {
		t.Errorf("host/source: %q %q", p.Host, p.Source)
	}
	if p.Message != "Failed password for admin" {
		t.Errorf("message: %q", p.Message)
	}
	if p.Severity != "informational" {
		t.Errorf("severity: %q (pri 134 = facility 16, sev 6)", p.Severity)
	}
	// No-year timestamp must be re-based to the current year.
	if p.Timestamp.Year() != time.Now().Year() {
		t.Errorf("year fixup: %v", p.Timestamp)
	}
}

func TestSyslog3164NoMatch(t *testing.T) {
	if _, ok := (syslog3164Parser{}).Parse([]byte("hello world")); ok {
		t.Error("non-syslog matched")
	}
}

func TestAutoDetectOrder(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`CEF:8|V|P|1|1|n|5|`, "cef"},
		{`LEEF:2.0 a=b!`, "leef"},
		{`{"version":"1.1","short_message":"x"}`, "gelf"},
		{`<134>1 2026-01-01T00:00:00Z h app - - msg`, "syslog5424"},
		{`<134>Sep  3 18:30:00 h app: msg`, "syslog3164"},
		{`plain text line`, "plain"},
	}
	for _, c := range cases {
		_, got := Default.Auto([]byte(c.raw))
		if got != c.want {
			t.Errorf("Auto(%q) = %q want %q", c.raw, got, c.want)
		}
	}
}

func TestFill(t *testing.T) {
	ev := &event.Event{SourceType: "syslog", Attributes: map[string]any{"keep": "me"}}
	p := &Parsed{
		Message:     "hello",
		Host:        "h",
		Severity:    "err",
		Timestamp:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Attributes:  map[string]any{"a": "b"},
	}
	Fill(ev, p)
	if ev.Message != "hello" || ev.Host != "h" || ev.Severity != "err" {
		t.Errorf("fill: %+v", ev)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp not filled")
	}
	if ev.SourceType != "syslog" {
		t.Error("Fill clobbered collector-set source_type")
	}
	if ev.Attributes["keep"] != "me" || ev.Attributes["a"] != "b" {
		t.Errorf("attrs: %v", ev.Attributes)
	}

	ev2 := &event.Event{Message: "original"}
	Fill(ev2, &Parsed{})
	if ev2.Message != "original" {
		t.Error("empty Parsed clobbered message")
	}
	Fill(nil, p) // must not panic
}
