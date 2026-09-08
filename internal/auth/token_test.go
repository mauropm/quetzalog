package auth_test

import (
	"context"
	"strings"
	"testing"

	"quetzalog/internal/auth"
	"quetzalog/internal/database"
)

// newStoreWithAuthTables creates a DB with the auth-owned tables exactly as the
// auth package's own schema definitions expect (this mirrors what migrations must
// provide once wired, and matches initTables definitions).
func newStoreWithAuthTables(t *testing.T) *auth.Store {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	schema := `
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'viewer',
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		last_login_at DATETIME,
		failed_login_count INTEGER NOT NULL DEFAULT 0,
		locked_until DATETIME
	);
	CREATE TABLE api_tokens (
		id TEXT PRIMARY KEY,
		token_hash TEXT NOT NULL UNIQUE,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	CREATE TABLE audit_log (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		details TEXT,
		ip TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return auth.NewStore(db)
}

func mustUser(t *testing.T, s *auth.Store, name, pass, role string) {
	t.Helper()
	if err := s.CreateUser(context.Background(), name, pass, role); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
}

func TestToken_NotSelfHashedAndUnpredictable(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()
	mustUser(t, s, "alice", "pass1234", auth.RoleViewer)
	u, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	tok1, err := s.CreateAPIToken(ctx, u.ID, "login")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	tok2, err := s.CreateAPIToken(ctx, u.ID, "login")
	if err != nil {
		t.Fatalf("create token2: %v", err)
	}
	if tok1 == tok2 {
		t.Error("tokens collide")
	}
	// The presented credential must not be merely the storage-side digest of
	// attacker-known inputs (name:user:timestamp). A leaked DB dump must not
	// double as a credential store.
	if tok1 == s.HashToken(tok1) {
		t.Errorf("token is its own hash (stored secret == bearer credential); token=%s", tok1)
	}
	// Validate must still accept the issued token.
	if _, err := s.ValidateAPIToken(ctx, tok1); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
	// And reject garbage.
	if _, err := s.ValidateAPIToken(ctx, strings.Repeat("0", 64)); err == nil {
		t.Error("random garbage validated")
	}
}

func TestAuthenticate_HappyAndFailure(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()
	mustUser(t, s, "bob", "hunter2234", auth.RoleAnalyst)

	u, err := s.Authenticate(ctx, "bob", "hunter2234")
	if err != nil || u.Username != "bob" {
		t.Fatalf("auth: %v", err)
	}
	if _, err := s.Authenticate(ctx, "bob", "bad"); err != auth.ErrInvalidCredentials {
		t.Errorf("want ErrInvalidCredentials got %v", err)
	}
	if _, err := s.Authenticate(ctx, "ghost", "bad"); err != auth.ErrInvalidCredentials {
		t.Errorf("unknown user must not leak enumeration info, got %v", err)
	}
}

func TestAuthenticate_LocksAfterFiveFailures(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()
	mustUser(t, s, "carol", "goodpass1", auth.RoleViewer)

	for i := 0; i < 5; i++ {
		_, _ = s.Authenticate(ctx, "carol", "wrong")
	}
	if _, err := s.Authenticate(ctx, "carol", "goodpass1"); err != auth.ErrAccountDisabled {
		t.Errorf("account should be locked after 5 failures, got %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()

	if err := s.CreateUser(ctx, "shorty", "abc", auth.RoleViewer); err != auth.ErrPasswordTooShort {
		t.Errorf("short password accepted: %v", err)
	}
	if err := s.CreateUser(ctx, "badrole", "abcdef1", "superuser"); err != auth.ErrInvalidRole {
		t.Errorf("bad role accepted: %v", err)
	}
	mustUser(t, s, "dan", "abcdef1", auth.RoleViewer)
	if err := s.CreateUser(ctx, "dan", "abcdef1", auth.RoleViewer); err != auth.ErrUserExists {
		t.Errorf("duplicate accepted: %v", err)
	}

	u, err := s.GetUserByUsername(ctx, "dan")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "dan", "abcdef1"); err != auth.ErrAccountDisabled {
		t.Errorf("disabled user authenticated: %v", err)
	}
	if err := s.EnableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "dan", "abcdef1"); err != nil {
		t.Errorf("re-enable failed: %v", err)
	}

	if err := s.UpdatePassword(ctx, u.ID, "newsecret1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "dan", "newsecret1"); err != nil {
		t.Errorf("new password rejected: %v", err)
	}

	list, err := s.ListUsers(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("list %d %v", len(list), err)
	}
	// List must not expose hashes.
	for _, lu := range list {
		if lu.PasswordHash != "" {
			t.Errorf("password hash leaked in ListUsers: %s", lu.PasswordHash)
		}
	}
}

func TestUpdateUser_NilSafeSemantics(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()
	mustUser(t, s, "eve", "abcdef1", auth.RoleViewer)
	u, _ := s.GetUserByUsername(ctx, "eve")

	enabled := false
	if err := s.UpdateUser(ctx, u.ID, "", "", &enabled); err != nil {
		t.Fatalf("update enabled: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.Enabled {
		t.Error("enabled=false not persisted")
	}
	if err := s.UpdateUser(ctx, u.ID, "", "superrole", nil); err != auth.ErrInvalidRole {
		t.Errorf("invalid role accepted via UpdateUser: %v", err)
	}
}

func TestLogAudit_Writes(t *testing.T) {
	s := newStoreWithAuthTables(t)
	if err := s.LogAudit(context.Background(), "uid", "act", "res", "det", "1.2.3.4"); err != nil {
		t.Fatalf("LogAudit failed against its own schema: %v", err)
	}
}

func TestDeleteUser_LastAdminGuard(t *testing.T) {
	s := newStoreWithAuthTables(t)
	ctx := context.Background()
	mustUser(t, s, "root", "abcdef1", auth.RoleAdmin)
	root, _ := s.GetUserByUsername(ctx, "root")
	if err := s.DeleteUser(ctx, root.ID); err != auth.ErrUserIsAdmin {
		t.Errorf("last admin deletable (%v) — lockout risk", err)
	}
}
