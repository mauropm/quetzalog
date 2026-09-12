package mitre

import (
	"testing"
)

func TestTactics(t *testing.T) {
	tactics := Tactics()
	if len(tactics) < 10 {
		t.Fatalf("too few tactics: %d", len(tactics))
	}
	ids := map[string]bool{}
	for _, tactic := range tactics {
		if tactic.ID == "" || tactic.Name == "" {
			t.Errorf("incomplete tactic: %+v", tactic)
		}
		ids[tactic.ID] = true
	}
	for _, want := range []string{"TA0001", "TA0006", "TA0010", "TA0040"} {
		if !ids[want] {
			t.Errorf("missing tactic %s", want)
		}
	}
}

func TestTechniques(t *testing.T) {
	techs := Techniques()
	if len(techs) < 50 {
		t.Fatalf("too few techniques: %d", len(techs))
	}
	for _, tech := range techs {
		if len(tech.TacticIDs) == 0 {
			t.Errorf("technique %s has no tactics", tech.ID)
		}
	}
}

func TestLookup(t *testing.T) {
	tech, ok := Lookup("t1059.001")
	if !ok || tech.ID != "T1059.001" {
		t.Errorf("lookup = %+v ok=%v", tech, ok)
	}
	if tech.SubOf != "T1059" {
		t.Errorf("SubOf = %q, want T1059", tech.SubOf)
	}
	if _, ok := Lookup("T9999"); ok {
		t.Error("expected unknown technique to miss")
	}
}

func TestTacticNameAndParent(t *testing.T) {
	name, ok := TacticName("ta0006")
	if !ok || name != "Credential Access" {
		t.Errorf("TacticName = %q ok=%v", name, ok)
	}
	if parent := ParentOf("T1059.001"); parent != "T1059" {
		t.Errorf("ParentOf = %q", parent)
	}
	if parent := ParentOf("T1059"); parent != "" {
		t.Errorf("top-level parent = %q, want empty", parent)
	}
}
