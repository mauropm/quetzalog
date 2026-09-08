package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"quetzalog/pkg/event"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidRole        = errors.New("invalid role: must be admin, analyst, or viewer")
	ErrPasswordTooShort   = errors.New("password too short")
	ErrUserIsAdmin        = errors.New("cannot delete the last admin user")
)

const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	Enabled      bool       `json:"enabled"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	FailedLogin  int        `json:"-"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    *time.Time `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at"`
}

type Token struct {
	ID        string     `json:"id"`
	Token     string     `json:"-"`
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`
	Enabled   bool       `json:"enabled"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type AuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// AuthCtxKey is the context key for the auth header value.
type AuthCtxKey struct{}

// AuthMiddleware returns middleware that validates an API token and sets
// the user in the request context.
func (s *Store) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization scheme", http.StatusUnauthorized)
				return
			}

			token, err := s.ValidateAPIToken(r.Context(), parts[1])
			if err != nil {
				http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
				return
			}

			user, err := s.GetUser(r.Context(), token.UserID)
			if err != nil {
				http.Error(w, "user not found", http.StatusUnauthorized)
				return
			}
			if !user.Enabled {
				http.Error(w, "account disabled", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), AuthCtxKey{}, authHeader)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// EnsureSchema installs the auth-owned tables and creates a default admin when
// the user table is empty. It is idempotent and should be called after migration.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.initTables(ctx)
}

func (s *Store) initTables(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
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
		)`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			details TEXT,
			ip TEXT,
			created_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)`,
	}

	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("execute migration: %w", err)
		}
	}

	return s.ensureDefaultAdmin(ctx)
}

func (s *Store) ensureDefaultAdmin(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("check users: %w", err)
	}

	if count == 0 {
		hashed, err := s.HashPassword("changeme")
		if err != nil {
			return fmt.Errorf("hash default password: %w", err)
		}

		id := event.GenerateEventID()
		now := time.Now().UTC()
		_, err = s.db.ExecContext(ctx,
			"INSERT INTO users (id, username, password_hash, role, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			id, "admin", hashed, RoleAdmin, true, now, now,
		)
		if err != nil {
			return fmt.Errorf("create default admin: %w", err)
		}
	}

	return nil
}

func (s *Store) CreateUser(ctx context.Context, username, password, role string) error {
	if len(password) < 4 {
		return ErrPasswordTooShort
	}

	if role == "" {
		role = RoleViewer
	}

	switch role {
	case RoleAdmin, RoleAnalyst, RoleViewer:
	default:
		return ErrInvalidRole
	}

	var exists int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&exists); err != nil {
		return fmt.Errorf("check user existence: %w", err)
	}
	if exists > 0 {
		return ErrUserExists
	}

	hashed, err := s.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	id := event.GenerateEventID()
	now := time.Now().UTC()

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash, role, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, username, hashed, role, true, now, now,
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

func (s *Store) Authenticate(ctx context.Context, username, password string) (*User, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.Enabled {
		return nil, ErrAccountDisabled
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountDisabled
	}

	if !s.CheckPassword(user.PasswordHash, password) {
		s.incrementFailedLogins(ctx, user.ID)
		return nil, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET failed_login_count = 0, last_login_at = ?, locked_until = NULL, updated_at = ? WHERE id = ?",
		now, now, user.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("update login info: %w", err)
	}

	user.LastLoginAt = &now
	return user, nil
}

func (s *Store) incrementFailedLogins(ctx context.Context, userID string) {
	now := time.Now().UTC()
	var failedCount int
	err := s.db.QueryRowContext(ctx, "SELECT failed_login_count FROM users WHERE id = ?", userID).Scan(&failedCount)
	if err != nil {
		return
	}
	failedCount++

	if failedCount >= 5 {
		lockedUntil := now.Add(15 * time.Minute)
		s.db.ExecContext(ctx,
			"UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?",
			failedCount, lockedUntil, now, userID,
		)
	} else {
		s.db.ExecContext(ctx,
			"UPDATE users SET failed_login_count = ?, updated_at = ? WHERE id = ?",
			failedCount, now, userID,
		)
	}
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	user := &User{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, role, enabled, created_at, updated_at, last_login_at, failed_login_count, locked_until FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Enabled,
		&user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.FailedLogin, &user.LockedUntil)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user: %w", err)
	}

	return user, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, role, enabled, created_at, updated_at, last_login_at, failed_login_count, locked_until FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Enabled,
		&user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.FailedLogin, &user.LockedUntil)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user by username: %w", err)
	}

	return user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, role, enabled, created_at, updated_at FROM users ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}

	return users, rows.Err()
}

func (s *Store) UpdatePassword(ctx context.Context, userID, newPassword string) error {
	if len(newPassword) < 4 {
		return ErrPasswordTooShort
	}

	hashed, err := s.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		hashed, now, userID,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	var isAdmin int
	var userCount int

	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM users WHERE role = ? AND id != ?", RoleAdmin, id).Scan(&isAdmin)
	if err != nil {
		return fmt.Errorf("check remaining admins: %w", err)
	}

	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id != ?", id).Scan(&userCount)
	if err != nil {
		return fmt.Errorf("check user count: %w", err)
	}

	if isAdmin == 0 || userCount == 0 {
		return ErrUserIsAdmin
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET enabled = 0, updated_at = ? WHERE id = ?",
		now, id,
	)
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}

	return nil
}

func (s *Store) UpdateUserRole(ctx context.Context, id, role string) error {
	switch role {
	case RoleAdmin, RoleAnalyst, RoleViewer:
	default:
		return ErrInvalidRole
	}

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
		role, now, id,
	)
	if err != nil {
		return fmt.Errorf("update user role: %w", err)
	}

	return nil
}

func (s *Store) EnableUser(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET enabled = 1, locked_until = NULL, failed_login_count = 0, updated_at = ? WHERE id = ?",
		now, id,
	)
	if err != nil {
		return fmt.Errorf("enable user: %w", err)
	}

	return nil
}

func (s *Store) DisableUser(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET enabled = 0, updated_at = ? WHERE id = ?",
		now, id,
	)
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}

	return nil
}

func (s *Store) UpdateUser(ctx context.Context, id, username, role string, enabled *bool) error {
	var usernameSet, roleSet bool
	if username != "" {
		usernameSet = true
	}
	if role != "" {
		roleSet = true
	}

	if !usernameSet && !roleSet && enabled == nil {
		return nil
	}

	if roleSet {
		switch role {
		case RoleAdmin, RoleAnalyst, RoleViewer:
		default:
			return ErrInvalidRole
		}
	}

	var setClauses []string
	var args []interface{}

	if usernameSet {
		setClauses = append(setClauses, "username = ?")
		args = append(args, username)
	}
	if roleSet {
		setClauses = append(setClauses, "role = ?")
		args = append(args, role)
	}
	if enabled != nil {
		var e int
		if *enabled {
			e = 1
		}
		setClauses = append(setClauses, "enabled = ?")
		args = append(args, e)
	}

	now := time.Now().UTC()
	setClauses = append(setClauses, "updated_at = ?")
	args = append(args, now)
	args = append(args, id)

	setSQL := strings.Join(setClauses, ", ")
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?", setSQL)

	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

func (s *Store) CreateAPIToken(ctx context.Context, userID, name string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	secret := "siem_" + hex.EncodeToString(raw)
	hashed := s.HashToken(secret)

	id := event.GenerateEventID()
	now := time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO api_tokens (id, token_hash, user_id, name, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, hashed, userID, name, true, now,
	)
	if err != nil {
		return "", fmt.Errorf("insert token: %w", err)
	}

	return secret, nil
}

// RevokeAPITokenByValue revokes the token record for a presented bearer token.
func (s *Store) RevokeAPITokenByValue(ctx context.Context, token string) error {
	hashed := s.HashToken(token)
	result, err := s.db.ExecContext(ctx, "UPDATE api_tokens SET enabled = 0 WHERE token_hash = ?", hashed)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

func (s *Store) ValidateAPIToken(ctx context.Context, token string) (*Token, error) {
	var t Token
	var stored sql.NullString
	hashed := s.HashToken(token)
	err := s.db.QueryRowContext(ctx,
		"SELECT id, token_hash, user_id, name, enabled, created_at FROM api_tokens WHERE token_hash = ?",
		hashed,
	).Scan(&t.ID, &stored, &t.UserID, &t.Name, &t.Enabled, &t.CreatedAt)
	if err == nil {
		t.Token = stored.String
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query token: %w", err)
	}

	if !t.Enabled {
		return nil, fmt.Errorf("token revoked")
	}

	return &t, nil
}

func (s *Store) RevokeAPIToken(ctx context.Context, tokenID string) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE api_tokens SET enabled = 0 WHERE id = ?", tokenID)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

func (s *Store) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (s *Store) CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *Store) HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Store) LogAudit(ctx context.Context, userID, action, resource, details, ip string) error {
	id := event.GenerateEventID()
	now := time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO audit_log (id, user_id, action, resource, details, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, userID, action, resource, details, ip, now,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}

	return nil
}
