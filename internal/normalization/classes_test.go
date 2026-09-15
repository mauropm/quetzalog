package normalization

import "testing"

func TestClassFor(t *testing.T) {
	// Taxonomy values map to themselves.
	if got := ClassFor(ClassWinSecurity); got != ClassWinSecurity {
		t.Errorf("ClassFor(win security) = %q", got)
	}
	if got := ClassFor(ClassGeneric); got != ClassGeneric {
		t.Errorf("ClassFor(generic) = %q", got)
	}
	// Transport/legacy source types have no inherent concern.
	for _, st := range []string{"syslog", "file:json", "hec_raw", "json", "otlp", "windows"} {
		if got := ClassFor(st); got != ClassGeneric {
			t.Errorf("ClassFor(%q) = %q, want generic", st, got)
		}
	}
}

func TestIsKnownClass(t *testing.T) {
	if !IsKnownClass(ClassNetFirewall) {
		t.Error("net.firewall should be known")
	}
	if IsKnownClass("not.a.class") {
		t.Error("unknown class reported known")
	}
}

func TestAllClassesUnique(t *testing.T) {
	seen := make(map[string]bool, len(AllClasses))
	for _, c := range AllClasses {
		if c == "" {
			t.Error("empty class in AllClasses")
		}
		if seen[c] {
			t.Errorf("duplicate class %q", c)
		}
		seen[c] = true
	}
}
