// Package sqlite3 — github.com/hanzoai/sqlite3
//
// Canonical Hanzo SQLite. Fork of ncruces/go-sqlite3 (pure-Go, WASM; no cgo)
// with a first-class native encrypted VFS (subpackage hanzovfs) backing
// per-tenant SQLite on hanzoai/vfs ⇒ S3 (HIP-0302 / HIP-0107), no FUSE.
//
// DEPRECATES:
//   - modernc.org/sqlite      — no custom-VFS hook; cannot do SQLite⇒VFS natively.
//   - github.com/ncruces/go-sqlite3 (direct) — use this fork so the hanzovfs
//     driver + Hanzo build pins travel with the platform.
package sqlite3
