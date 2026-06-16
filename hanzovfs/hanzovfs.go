package hanzovfs

import (
	"crypto/rand"
	"sync"

	"github.com/hanzoai/sqlite3/vfs"
	"golang.org/x/crypto/chacha20poly1305"
)

// encVFS: a native (no-FUSE) SQLite VFS that stores the DB as fixed-size
// blocks, each sealed with ChaCha20-Poly1305 (per-page AEAD) — the design a
// real hanzoai/vfs Go driver would use instead of FUSE + per-block age messages.
const blockSize = 4096

type encVFS struct{ aead bool }

func (v encVFS) Open(name string, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	f := &encFile{blocks: map[int64][]byte{}, aead: v.aead}
	if v.aead {
		key := make([]byte, chacha20poly1305.KeySize)
		rand.Read(key)
		f.c, _ = chacha20poly1305.New(key)
	}
	return f, flags, nil
}
func (encVFS) Delete(string, bool) error              { return nil }
func (encVFS) Access(string, vfs.AccessFlag) (bool, error) { return false, nil }
func (encVFS) FullPathname(name string) (string, error)   { return name, nil }

type encFile struct {
	mu     sync.Mutex
	blocks map[int64][]byte // plaintext page cache
	enc    map[int64][]byte // sealed pages (the "backend")
	size   int64
	aead   bool
	c      interface{ Seal([]byte, []byte, []byte, []byte) []byte; Open([]byte, []byte, []byte, []byte) ([]byte, error); NonceSize() int }
}

func (f *encFile) loadBlock(idx int64) []byte {
	if b, ok := f.blocks[idx]; ok {
		return b
	}
	b := make([]byte, blockSize)
	if f.enc != nil {
		if sealed, ok := f.enc[idx]; ok && f.aead {
			ns := f.c.NonceSize()
			pt, err := f.c.Open(nil, sealed[:ns], sealed[ns:], nil)
			if err == nil {
				copy(b, pt)
			}
		}
	}
	f.blocks[idx] = b
	return b
}
func (f *encFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	n := 0
	for n < len(p) {
		idx := (off + int64(n)) / blockSize
		bo := int((off + int64(n)) % blockSize)
		b := f.loadBlock(idx)
		c := copy(p[n:], b[bo:])
		n += c
	}
	return n, nil
}
func (f *encFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	n := 0
	for n < len(p) {
		idx := (off + int64(n)) / blockSize
		bo := int((off + int64(n)) % blockSize)
		b := f.loadBlock(idx)
		c := copy(b[bo:], p[n:])
		f.blocks[idx] = b
		// seal the page (write-through to the "backend")
		if f.aead {
			if f.enc == nil { f.enc = map[int64][]byte{} }
			ns := f.c.NonceSize()
			nonce := make([]byte, ns); rand.Read(nonce)
			f.enc[idx] = append(nonce, f.c.Seal(nil, nonce, b, nil)...)
		}
		n += c
		if off+int64(n) > f.size { f.size = off + int64(n) }
	}
	return n, nil
}
func (f *encFile) Truncate(s int64) error { f.mu.Lock(); f.size = s; f.mu.Unlock(); return nil }
func (f *encFile) Sync(vfs.SyncFlag) error { return nil }
func (f *encFile) Size() (int64, error)    { return f.size, nil }
func (f *encFile) Close() error            { return nil }
func (f *encFile) Lock(vfs.LockLevel) error          { return nil }
func (f *encFile) Unlock(vfs.LockLevel) error        { return nil }
func (f *encFile) CheckReservedLock() (bool, error)  { return false, nil }
func (f *encFile) SectorSize() int                   { return blockSize }
func (f *encFile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	return vfs.IOCAP_ATOMIC | vfs.IOCAP_SAFE_APPEND | vfs.IOCAP_SEQUENTIAL
}
