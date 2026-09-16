package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EventToken is a shareable ingest API key: it may only POST events
// (/api/v1/events, /api/v1/events/batch) and grants no control-plane access.
//
// The plaintext token is stored ENCRYPTED (AES-256-GCM under a machine-local
// key) so an admin can re-copy it later; a SHA-256 hash is stored separately
// for constant-time validation on the ingest hot path.
type EventToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Tag         string     `json:"tag"`
	Group       string     `json:"group"`
	Enabled     bool       `json:"enabled"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	TokenPrefix string    `json:"token_prefix"` // first characters, shown masked
	Token       string    `json:"-"`            // full token, only on create/reveal
}

// eventTokenKeyFile is the machine-local AES key. It lives next to the
// database: without the machine (or a copy of its data dir) encrypted tokens
// cannot be revealed.
const eventTokenKeyFile = "event-token.key"

func eventTokenKeyPath(dbDir string) string { return filepath.Join(dbDir, eventTokenKeyFile) }

// LoadOrCreateEncryptionKey reads the machine key, creating it (32 random
// bytes, 0600) when missing.
func LoadOrCreateEncryptionKey(dbDir string) ([]byte, error) {
	p := eventTokenKeyPath(dbDir)
	if data, err := os.ReadFile(p); err == nil && len(data) == 32 {
		return data, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(p, key, 0o600); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}
	return key, nil
}

// LoadEncryptionKey reads the machine key without creating it.
func LoadEncryptionKey(dbDir string) ([]byte, error) {
	data, err := os.ReadFile(eventTokenKeyPath(dbDir))
	if err != nil {
		return nil, fmt.Errorf("load encryption key: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("encryption key has invalid length %d", len(data))
	}
	return data, nil
}

func encryptToken(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Seal does not include the nonce in its output — prepend it.
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return append(append([]byte{}, nonce...), sealed...), nil
}

func decryptToken(key []byte, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	plain, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return string(plain), nil
}

// EventTokenStore persists event tokens.
type EventTokenStore struct {
	db  *sql.DB
	key []byte
}

// NewEventTokenStore wraps db; keyDir is the directory holding the machine
// encryption key (usually the database directory).
func NewEventTokenStore(db *sql.DB, keyDir string) (*EventTokenStore, error) {
	key, err := LoadOrCreateEncryptionKey(keyDir)
	if err != nil {
		return nil, err
	}
	return &EventTokenStore{db: db, key: key}, nil
}

// NewEventTokenStoreWithKey wraps db with an explicit machine key
// (tests, or a caller that already owns the key file).
func NewEventTokenStoreWithKey(db *sql.DB, key []byte) *EventTokenStore {
	return &EventTokenStore{db: db, key: key}
}

func (s *EventTokenStore) ensureTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS event_tokens (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		tag TEXT NOT NULL DEFAULT '',
		grp TEXT NOT NULL DEFAULT '',
		token_hash TEXT NOT NULL UNIQUE,
		token_enc BLOB NOT NULL,
		token_prefix TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_by TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("create event_tokens: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_event_tokens_hash ON event_tokens(token_hash)`)
	if err != nil {
		return fmt.Errorf("index event_tokens hash: %w", err)
	}
	return nil
}

func generateEventTokenValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "qev_" + hex.EncodeToString(raw), nil
}

// Create stores a new event token and returns its full value exactly once
// at creation (it can be re-revealed later only by an admin).
func (s *EventTokenStore) Create(ctx context.Context, name, tag, group, createdBy string) (*EventToken, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("event token store not available")
	}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	if name == "" {
		name = "event token"
	}
	secret, err := generateEventTokenValue()
	if err != nil {
		return nil, err
	}
	enc, err := encryptToken(s.key, secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt token: %w", err)
	}
	hashed := sha256.Sum256([]byte(secret))

	id := "evt-" + hex.EncodeToString(func() []byte {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return b
	}())
	now := time.Now().UTC()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO event_tokens (id, name, tag, grp, token_hash, token_enc, token_prefix, enabled, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		id, name, tag, group, hex.EncodeToString(hashed[:]), enc, secret[:12], createdBy, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert event token: %w", err)
	}
	return &EventToken{
		ID:          id,
		Name:        name,
		Tag:         tag,
		Group:       group,
		Enabled:     true,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
		TokenPrefix: secret[:12],
		Token:       secret,
	}, nil
}

// List returns tokens WITHOUT the encrypted material (masked view).
func (s *EventTokenStore) List(ctx context.Context) ([]EventToken, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("event token store not available")
	}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, tag, grp, token_prefix, enabled, created_by, created_at, updated_at
		 FROM event_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list event tokens: %w", err)
	}
	defer rows.Close()

	out := []EventToken{}
	for rows.Next() {
		var t EventToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Tag, &t.Group, &t.TokenPrefix, &t.Enabled, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan event token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Reveal decrypts and returns the full token for one record (admin-only at
// the API layer).
func (s *EventTokenStore) Reveal(ctx context.Context, id string) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("event token store not available")
	}
	var enc []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT token_enc FROM event_tokens WHERE id = ?`, id).Scan(&enc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("event token not found")
		}
		return "", fmt.Errorf("load event token: %w", err)
	}
	return decryptToken(s.key, enc)
}

// UpdateNameTags renames / retags / regroups a token.
func (s *EventTokenStore) UpdateNameTags(ctx context.Context, id, name, tag, group string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("event token store not available")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE event_tokens SET name = ?, tag = ?, grp = ?, updated_at = ? WHERE id = ?`,
		name, tag, group, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update event token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("event token not found")
	}
	return nil
}

// Expire disables a token so it no longer authorizes ingest.
func (s *EventTokenStore) Expire(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("event token store not available")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE event_tokens SET enabled = 0, updated_at = ? WHERE id = ?`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("expire event token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("event token not found")
	}
	return nil
}

// Delete removes a token permanently.
func (s *EventTokenStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("event token store not available")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM event_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete event token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("event token not found")
	}
	return nil
}

// Validate checks a presented bearer value against stored event tokens.
func (s *EventTokenStore) Validate(ctx context.Context, token string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("event token store not available")
	}
	if err := s.ensureTable(ctx); err != nil {
		return false, err
	}
	hashed := sha256.Sum256([]byte(token))
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT enabled FROM event_tokens WHERE token_hash = ?`,
		hex.EncodeToString(hashed[:])).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("validate event token: %w", err)
	}
	return enabled == 1, nil
}
