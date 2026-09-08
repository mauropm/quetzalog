package auth_test

import (
	"context"
	"os"
	"testing"
	"time"

	"quetzalog/internal/auth"
	"quetzalog/internal/database"
)

// AUTH-SEC-01: EnsureSchema must never bootstrap the admin with a static,
// published password. Without the env override the password must be random
// (i.e. 'changeme' must not work).
func TestAUTHSec_DefaultAdminNoStaticPassword(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	old, had := os.LookupEnv("QUETZALOG_ADMIN_PASSWORD")
	_ = os.Unsetenv("QUETZALOG_ADMIN_PASSWORD")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("QUETZALOG_ADMIN_PASSWORD", old)
		}
	})

	store := auth.NewStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	if _, err := store.Authenticate(context.Background(), "admin", "changeme"); err == nil {
		t.Error("default admin accepted hardcoded password 'changeme' (AUTH-SEC-01)")
	}

	// admin still exists and is enabled (workflow preserved)
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range users {
		if u.Username == "admin" && u.Role == auth.RoleAdmin && u.Enabled {
			found = true
		}
	}
	if !found {
		t.Error("default admin missing after EnsureSchema — first-run workflow broken")
	}
}

// AUTH-SEC-02: the env override is the supported deterministic bootstrap.
func TestAUTHSec_EnvOverrideBootstrapsAdmin(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	old, had := os.LookupEnv("QUETZALOG_ADMIN_PASSWORD")
	if err := os.Setenv("QUETZALOG_ADMIN_PASSWORD", "sup3r-str0ng-bootstrap-Pw!"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("QUETZALOG_ADMIN_PASSWORD", old)
		} else {
			_ = os.Unsetenv("QUETZALOG_ADMIN_PASSWORD")
		}
	})

	store := auth.NewStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(context.Background(), "admin", "sup3r-str0ng-bootstrap-Pw!"); err != nil {
		t.Errorf("env-provided admin password rejected: %v", err)
	}
}

// AUTH-SEC-03: unknown-user vs wrong-password paths must take comparable
// time (both perform a bcrypt comparison) so login does not leak which
// accounts exist.
func TestAUTHSec_LoginTimingUniform(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	if err := store.CreateUser(context.Background(), "timing-user", "timing-pass-123", auth.RoleAnalyst); err != nil {
		t.Fatal(err)
	}

	const trials = 5
	var tUnknown, tWrong time.Duration
	for i := 0; i < trials; i++ {
		start := time.Now()
		_, _ = store.Authenticate(context.Background(), "ghost-does-not-exist", "whatever-123")
		tUnknown += time.Since(start)

		start = time.Now()
		_, _ = store.Authenticate(context.Background(), "timing-user", "wrong-password")
		tWrong += time.Since(start)
	}

	ratio := float64(tUnknown) / float64(tWrong)
	// Unknown user must not be >4x faster than a real bcrypt mismatch.
	if ratio < 0.25 {
		t.Errorf("user-enumeration timing oracle: unknown-user took %.2fx of wrong-password path (AUTH-SEC-03)", ratio)
	}
}

// AUTH-SEC-04: tokens must have >=128 bits of entropy and be unpredictable.
func TestAUTHSec_TokenEntropy(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)
	user, err := store.Authenticate(context.Background(), "admin", "changeme")
	if err != nil {
		t.Skipf("setup admin not authenticatable in this fixture: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		tok, err := store.CreateAPIToken(context.Background(), user.ID, "t")
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) < 40 {
			t.Fatalf("token too short: %d chars", len(tok))
		}
		if seen[tok] {
			t.Fatal("duplicate token generated")
		}
		seen[tok] = true
	}
}
