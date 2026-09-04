package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"quetzalog/internal/auth"
	"quetzalog/internal/database"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create auth tables directly (without FTS5 which isn't available in memory)
	createTables := `
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
			token_hash TEXT NOT NULL,
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
			created_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash);
		CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
		CREATE INDEX idx_audit_log_user ON audit_log(user_id);
		CREATE INDEX idx_audit_log_action ON audit_log(action);
		CREATE INDEX idx_audit_log_created ON audit_log(created_at);
	`
	if _, err := db.Exec(createTables); err != nil {
		t.Fatalf("create auth tables: %v", err)
	}

	// Insert default admin user (same as ensureDefaultAdmin)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users (id, username, password_hash, role, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"550e8400-e29b-41d4-a716-446655440000", "admin", string(hashed), "admin", 1, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))

	return db
}

func TestHashPassword_ValidHash(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	hash, err := store.HashPassword("test-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if len(hash) < 20 {
		t.Fatalf("expected bcrypt hash (min 20 chars), got %d chars", len(hash))
	}

	if hash[:4] != "$2a$" {
		t.Fatalf("expected bcrypt hash starting with $2a$, got: %s", hash[:4])
	}
}

func TestCheckPassword_ValidAndInvalid(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	password := "my-secure-password"
	hash, err := store.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !store.CheckPassword(hash, password) {
		t.Fatal("expected CheckPassword to return true for correct password")
	}

	if store.CheckPassword(hash, "wrong-password") {
		t.Fatal("expected CheckPassword to return false for wrong password")
	}

	if store.CheckPassword(hash, "") {
		t.Fatal("expected CheckPassword to return false for empty password")
	}
}

func TestCreateUser_BcryptHash(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var hash string
	err = db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE username = ?", "testuser").Scan(&hash)
	if err != nil {
		t.Fatalf("query password_hash: %v", err)
	}

	if hash[:4] != "$2a$" {
		t.Fatalf("expected bcrypt hash, got: %s", hash[:4])
	}
}

func TestAuthenticate_CorrectPassword(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "password123")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestAuthenticate_UserNotFound(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	_, err := store.Authenticate(context.Background(), "nonexistent", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestAuthenticate_AccountDisabled(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "disableduser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = db.Exec("UPDATE users SET enabled = 0 WHERE username = ?", "disableduser")
	if err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "disableduser", "password123")
	if err == nil {
		t.Fatal("expected error for disabled account")
	}

	if err != auth.ErrAccountDisabled {
		t.Fatalf("expected ErrAccountDisabled, got: %v", err)
	}
}

func TestUpdatePassword(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "testuser").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	err = store.UpdatePassword(context.Background(), userID, "newpassword456")
	if err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "newpassword456")
	if err != nil {
		t.Fatalf("authenticate with new password: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "password123")
	if err == nil {
		t.Fatal("expected authentication with old password to fail")
	}
}

func TestUpdatePassword_TooShort(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	err := store.UpdatePassword(context.Background(), "some-id", "abc")
	if err == nil {
		t.Fatal("expected error for short password")
	}

	if err != auth.ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got: %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "deleteme", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "deleteme").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	err = store.DeleteUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	var enabled int
	err = db.QueryRowContext(context.Background(),
		"SELECT enabled FROM users WHERE id = ?", userID).Scan(&enabled)
	if err != nil {
		t.Fatalf("query enabled: %v", err)
	}

	if enabled != 0 {
		t.Fatal("expected user to be disabled after delete")
	}
}

func TestDeleteUser_LastAdminFails(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	// Create a non-admin user to trigger initTables (which creates default admin)
	err := store.CreateUser(context.Background(), "otheruser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Get the default admin user ID
	var adminID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = 'admin'").Scan(&adminID)
	if err != nil {
		t.Fatalf("query admin ID: %v", err)
	}

	err = store.DeleteUser(context.Background(), adminID)
	if err == nil {
		t.Fatal("expected error when deleting default admin (only admin)")
	}

	if err != auth.ErrUserIsAdmin {
		t.Fatalf("expected ErrUserIsAdmin, got: %v", err)
	}
}

func TestUpdateUserRole(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "testuser").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	err = store.UpdateUserRole(context.Background(), userID, auth.RoleAnalyst)
	if err != nil {
		t.Fatalf("UpdateUserRole: %v", err)
	}

	var role string
	err = db.QueryRowContext(context.Background(),
		"SELECT role FROM users WHERE id = ?", userID).Scan(&role)
	if err != nil {
		t.Fatalf("query role: %v", err)
	}

	if role != auth.RoleAnalyst {
		t.Fatalf("expected role analyst, got %s", role)
	}
}

func TestUpdateUserRole_InvalidRole(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	err := store.UpdateUserRole(context.Background(), "some-id", "superadmin")
	if err == nil {
		t.Fatal("expected error for invalid role")
	}

	if err != auth.ErrInvalidRole {
		t.Fatalf("expected ErrInvalidRole, got: %v", err)
	}
}

func TestEnableDisableUser(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "testuser").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	err = store.DisableUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "password123")
	if err == nil {
		t.Fatal("expected error for disabled user")
	}

	err = store.EnableUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("EnableUser: %v", err)
	}

	_, err = store.Authenticate(context.Background(), "testuser", "password123")
	if err != nil {
		t.Fatalf("expected success after re-enable: %v", err)
	}
}

func TestListUsers_NoPasswordHash(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}

	if users[0].PasswordHash != "" {
		t.Fatal("ListUsers should not include password hash")
	}
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}

	err = store.CreateUser(context.Background(), "testuser", "password456", auth.RoleViewer)
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}

	if err != auth.ErrUserExists {
		t.Fatalf("expected ErrUserExists, got: %v", err)
	}
}

func TestGetUserByID(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "testuser").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	_, err = store.GetUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	_, err := store.GetUser(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}

	if err != auth.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}
}

func TestGetUserByUsername(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = store.GetUserByUsername(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	_, err := store.GetUserByUsername(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}

	if err != auth.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var userID string
	err = db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username = ?", "testuser").Scan(&userID)
	if err != nil {
		t.Fatalf("query user ID: %v", err)
	}

	newUsername := "newusername"
	newRole := auth.RoleAnalyst
	enabled := true

	err = store.UpdateUser(context.Background(), userID, newUsername, newRole, &enabled)
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	var username, role string
	var enabledVal int
	err = db.QueryRowContext(context.Background(),
		"SELECT username, role, enabled FROM users WHERE id = ?", userID).
		Scan(&username, &role, &enabledVal)
	if err != nil {
		t.Fatalf("query updated user: %v", err)
	}

	if username != newUsername {
		t.Fatalf("expected username %s, got %s", newUsername, username)
	}
	if role != newRole {
		t.Fatalf("expected role %s, got %s", newRole, role)
	}
	if enabledVal != 1 {
		t.Fatal("expected enabled to be true")
	}
}

func TestDefaultAdminCreated(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	if len(users) == 0 {
		t.Fatal("expected default admin to be created")
	}

	var enabled int
	err = db.QueryRowContext(context.Background(),
		"SELECT enabled FROM users WHERE username = ?", "admin").Scan(&enabled)
	if err != nil {
		t.Fatalf("query default admin enabled: %v", err)
	}

	if enabled != 1 {
		t.Fatal("expected default admin to be enabled")
	}
}

func TestAuthenticate_LastLoginAtUpdated(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "testuser", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	user1, err := store.Authenticate(context.Background(), "testuser", "password123")
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	if user1.LastLoginAt == nil {
		t.Fatal("expected last_login_at after first authentication")
	}

	firstLogin := *user1.LastLoginAt

	time.Sleep(10 * time.Millisecond)

	user2, err := store.Authenticate(context.Background(), "testuser", "password123")
	if err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}

	if user2.LastLoginAt == nil {
		t.Fatal("expected last_login_at after second authentication")
	}

	if user2.LastLoginAt.Before(firstLogin) {
		t.Fatal("expected last_login_at to be updated")
	}
}

func TestFailedLoginLocksAccount(t *testing.T) {
	db := setupDB(t)
	store := auth.NewStore(db)

	err := store.CreateUser(context.Background(), "locktest", "password123", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for i := 0; i < 5; i++ {
		_, err := store.Authenticate(context.Background(), "locktest", "wrong")
		if err != auth.ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials on attempt %d, got: %v", i+1, err)
		}
	}

	var lockedAt string
	err = db.QueryRowContext(context.Background(),
		"SELECT locked_until FROM users WHERE username = ?", "locktest").Scan(&lockedAt)
	if err != nil {
		t.Fatalf("query locked_until: %v", err)
	}

	if lockedAt == "" {
		t.Fatal("expected account to be locked after 5 failed attempts")
	}

	_, err = store.Authenticate(context.Background(), "locktest", "password123")
	if err == nil {
		t.Fatal("expected authentication to fail for locked account")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	store := auth.NewStore(setupDB(t))

	hash1, err := store.HashPassword("same-password")
	if err != nil {
		t.Fatalf("first HashPassword: %v", err)
	}

	hash2, err := store.HashPassword("same-password")
	if err != nil {
		t.Fatalf("second HashPassword: %v", err)
	}

	if hash1 == hash2 {
		t.Fatal("expected different bcrypt hashes for same password (different salts)")
	}
}
