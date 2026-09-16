package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func etStoreForTest(t *testing.T) (*sql.DB, *EventTokenStore) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return db, NewEventTokenStoreWithKey(db, key)
}

func TestEventTokenLifecycle(t *testing.T) {
	db, s := etStoreForTest(t)
	_ = db
	ctx := context.Background()

	created, err := s.Create(ctx, "splunk-fwd", "splunk", "prod", "admin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Token == "" || created.Token[:4] != "qev_" {
		t.Fatalf("token format: %q", created.Token)
	}
	if created.TokenPrefix != created.Token[:12] {
		t.Errorf("prefix mismatch: %q vs %q", created.TokenPrefix, created.Token[:12])
	}

	ok, err := s.Validate(ctx, created.Token)
	if err != nil || !ok {
		t.Fatalf("validate valid token: ok=%v err=%v", ok, err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Token != "" || list[0].Name != "splunk-fwd" || list[0].Group != "prod" || list[0].Tag != "splunk" {
		t.Fatalf("list content: %+v", list)
	}
	if list[0].TokenPrefix != created.TokenPrefix {
		t.Errorf("masked prefix not preserved: %q", list[0].TokenPrefix)
	}

	revealed, err := s.Reveal(ctx, created.ID)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if revealed != created.Token {
		t.Fatalf("reveal returned %q, want the original token", revealed)
	}

	if err := s.UpdateNameTags(ctx, created.ID, "renamed", "siem", "staging"); err != nil {
		t.Fatalf("update: %v", err)
	}
	list, _ = s.List(ctx)
	if list[0].Name != "renamed" || list[0].Tag != "siem" || list[0].Group != "staging" {
		t.Fatalf("after update: %+v", list[0])
	}

	if err := s.Expire(ctx, created.ID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	ok, err = s.Validate(ctx, created.Token)
	if err != nil || ok {
		t.Fatalf("expired token must not validate: ok=%v err=%v", ok, err)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, _ = s.List(ctx)
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}
}

func TestEventTokenValidationUnknown(t *testing.T) {
	_, s := etStoreForTest(t)
	ok, err := s.Validate(context.Background(), "qev_unknown_value")
	if err != nil {
		t.Fatalf("validate unknown: %v", err)
	}
	if ok {
		t.Fatal("unknown token must not validate")
	}
}

func TestEventTokenEncryptDecryptRoundtripAndKeyMismatch(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(k2); err != nil {
		t.Fatal(err)
	}
	enc, err := encryptToken(k1, "qev_secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(enc, []byte("qev_secret")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	plain, err := decryptToken(k1, enc)
	if err != nil || plain != "qev_secret" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	if _, err := decryptToken(k2, enc); err == nil {
		t.Fatal("decrypt with a different key must fail")
	}
}

func TestEventTokenKeyFile(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateEncryptionKey(dir)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	k2, err := LoadOrCreateEncryptionKey(dir)
	if err != nil {
		t.Fatalf("reload key: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("key must be stable across loads")
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d", len(k1))
	}
	_ = time.Now()
}
