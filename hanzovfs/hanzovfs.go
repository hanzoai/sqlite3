// Package hanzovfs is the native, post-quantum SQLite VFS for github.com/hanzoai/sqlite3.
//
// A per-database data-encryption key (DEK) seals every 4 KiB page with
// ChaCha20-Poly1305. The DEK itself is sealed with luxfi/age PQ-hybrid
// (ML-KEM-768 + X25519) — so the path tenant page → encrypted block → backend
// object is end-to-end post-quantum: a quantum adversary that records the
// ciphertext still cannot recover the DEK. No FUSE, no cgo.
package hanzovfs

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hanzoai/sqlite3/vfs"
	"github.com/luxfi/age"
	"golang.org/x/crypto/chacha20poly1305"
)

const pageSize = 4096

// Config configures a per-tenant VFS. Recipients seal the DEK (write side);
// Identities open it (read side). Both are luxfi/age PQ-hybrid values.
type Config struct {
	Dir        string
	Recipients []age.Recipient
	Identities []age.Identity
}

// Register installs a named VFS: sqlite3.Open("file:/orgs/acme/app.db?vfs=NAME").
func Register(name string, cfg Config) { vfs.Register(name, &hvfs{cfg: cfg}) }

type hvfs struct{ cfg Config }

func sanitize(name string) string {
	name = strings.TrimPrefix(name, "/")
	name = strings.ReplaceAll(name, "..", "_")
	return strings.ReplaceAll(name, "/", "__")
}

func (v *hvfs) Open(name string, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	dir := filepath.Join(v.cfg.Dir, sanitize(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, 0, err
	}
	dek, err := loadOrCreateDEK(dir, v.cfg)
	if err != nil {
		return nil, 0, err
	}
	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, 0, err
	}
	f := &hfile{dir: dir, aead: aead}
	f.loadSize()
	return f, flags, nil
}

func (v *hvfs) Delete(name string, _ bool) error {
	return os.RemoveAll(filepath.Join(v.cfg.Dir, sanitize(name)))
}
func (v *hvfs) Access(name string, _ vfs.AccessFlag) (bool, error) {
	_, err := os.Stat(filepath.Join(v.cfg.Dir, sanitize(name), "dek.age"))
	return err == nil, nil
}
func (v *hvfs) FullPathname(name string) (string, error) { return name, nil }

// DEK is 32 random bytes sealed to dir/dek.age with the PQ-hybrid recipients.
func loadOrCreateDEK(dir string, cfg Config) ([]byte, error) {
	p := filepath.Join(dir, "dek.age")
	if b, err := os.ReadFile(p); err == nil {
		r, err := age.Decrypt(bytes.NewReader(b), cfg.Identities...)
		if err != nil {
			return nil, fmt.Errorf("hanzovfs: unseal DEK: %w", err)
		}
		dek, _ := io.ReadAll(r)
		if len(dek) != chacha20poly1305.KeySize {
			return nil, errors.New("hanzovfs: corrupt DEK")
		}
		return dek, nil
	}
	if len(cfg.Recipients) == 0 {
		return nil, errors.New("hanzovfs: no recipients to seal a new DEK")
	}
	dek := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, cfg.Recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(dek); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return dek, os.WriteFile(p, buf.Bytes(), 0o600)
}

type hfile struct {
	mu   sync.Mutex
	dir  string
	aead cipher.AEAD
	size int64
}

func (f *hfile) blk(i int64) string { return filepath.Join(f.dir, fmt.Sprintf("%012d.blk", i)) }
func (f *hfile) sizePath() string   { return filepath.Join(f.dir, "size") }

func (f *hfile) loadSize() {
	if b, err := os.ReadFile(f.sizePath()); err == nil {
		fmt.Sscanf(string(b), "%d", &f.size)
	}
}
func (f *hfile) page(i int64) ([]byte, error) {
	b, err := os.ReadFile(f.blk(i))
	if os.IsNotExist(err) {
		return make([]byte, pageSize), nil
	}
	if err != nil {
		return nil, err
	}
	ns := f.aead.NonceSize()
	pt, err := f.aead.Open(nil, b[:ns], b[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("hanzovfs: page %d auth failed: %w", i, err)
	}
	if len(pt) < pageSize {
		p := make([]byte, pageSize)
		copy(p, pt)
		return p, nil
	}
	return pt, nil
}
func (f *hfile) putPage(i int64, p []byte) error {
	ns := f.aead.NonceSize()
	nonce := make([]byte, ns)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	return os.WriteFile(f.blk(i), f.aead.Seal(nonce, nonce, p, nil), 0o600)
}

func (f *hfile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(p) {
		idx := (off + int64(n)) / pageSize
		bo := int((off + int64(n)) % pageSize)
		pg, err := f.page(idx)
		if err != nil {
			return n, err
		}
		n += copy(p[n:], pg[bo:])
	}
	return n, nil
}
func (f *hfile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(p) {
		idx := (off + int64(n)) / pageSize
		bo := int((off + int64(n)) % pageSize)
		pg, err := f.page(idx)
		if err != nil {
			return n, err
		}
		c := copy(pg[bo:], p[n:])
		if err := f.putPage(idx, pg); err != nil {
			return n, err
		}
		n += c
		if off+int64(n) > f.size {
			f.size = off + int64(n)
		}
	}
	return n, nil
}
func (f *hfile) Truncate(s int64) error {
	f.mu.Lock()
	f.size = s
	f.mu.Unlock()
	return f.Sync(0)
}
func (f *hfile) Sync(vfs.SyncFlag) error {
	return os.WriteFile(f.sizePath(), []byte(fmt.Sprintf("%d", f.size)), 0o600)
}
func (f *hfile) Size() (int64, error) { return f.size, nil }
func (f *hfile) Close() error         { return f.Sync(0) }

func (f *hfile) Lock(vfs.LockLevel) error         { return nil }
func (f *hfile) Unlock(vfs.LockLevel) error       { return nil }
func (f *hfile) CheckReservedLock() (bool, error) { return false, nil }
func (f *hfile) SectorSize() int                  { return pageSize }
func (f *hfile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	return vfs.IOCAP_ATOMIC | vfs.IOCAP_SAFE_APPEND | vfs.IOCAP_POWERSAFE_OVERWRITE
}
