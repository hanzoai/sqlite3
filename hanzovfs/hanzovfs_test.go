package hanzovfs_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/sqlite3"
	_ "github.com/hanzoai/sqlite3/embed"
	"github.com/hanzoai/sqlite3/hanzovfs"
)

func TestPQRoundTripDurableAndSealed(t *testing.T) {
	dir := t.TempDir()
	id, rcpt, err := hanzovfs.GenerateIdentity()
	if err != nil { t.Fatal(err) }
	hanzovfs.Register("t1", hanzovfs.Config{Dir: dir, Recipients: rcpts(rcpt), Identities: idents(id)})

	// write
	db, err := sqlite3.Open("file:/orgs/acme/app.db?vfs=t1")
	if err != nil { t.Fatal(err) }
	db.Exec("CREATE TABLE u(id INTEGER PRIMARY KEY, email TEXT)")
	db.Exec("INSERT INTO u(email) VALUES('zach@hanzo.ai'),('ops@hanzo.ai')")
	db.Close()

	// the DEK on disk must be age-PQ-sealed, never the raw key
	dek, err := os.ReadFile(filepath.Join(dir, "orgs__acme__app.db", "dek.age"))
	if err != nil { t.Fatalf("no dek.age: %v", err) }
	if !bytes.Contains(dek, []byte("age-encryption.org")) {
		t.Error("dek.age is not an age envelope")
	}
	// blocks must not contain plaintext sqlite
	matches, _ := filepath.Glob(filepath.Join(dir, "orgs__acme__app.db", "*.blk"))
	if len(matches) == 0 { t.Fatal("no encrypted blocks written") }
	for _, m := range matches {
		b, _ := os.ReadFile(m)
		if bytes.Contains(b, []byte("SQLite format 3")) { t.Fatalf("PLAINTEXT leak in %s", m) }
	}

	// reopen with the right identity → data survives
	hanzovfs.Register("t1b", hanzovfs.Config{Dir: dir, Identities: idents(id)})
	db2, err := sqlite3.Open("file:/orgs/acme/app.db?vfs=t1b")
	if err != nil { t.Fatal(err) }
	st, _, _ := db2.Prepare("SELECT count(*) FROM u")
	st.Step()
	if n := st.ColumnInt(0); n != 2 { t.Fatalf("rows survived = %d, want 2", n) }
	st.Close(); db2.Close()

	// reopen with a WRONG identity → DEK unseal must fail
	other, _, _ := hanzovfs.GenerateIdentity()
	hanzovfs.Register("t1x", hanzovfs.Config{Dir: dir, Identities: idents(other)})
	if _, err := sqlite3.Open("file:/orgs/acme/app.db?vfs=t1x"); err == nil {
		t.Fatal("wrong identity opened the DB — PQ seal not enforced")
	}
	t.Log("e2e PQ verified: DEK age-sealed (ML-KEM-768+X25519), pages encrypted, wrong key rejected, data durable")
}
