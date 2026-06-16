// hanzovfs-bench measures the native Hanzo SQLite VFS (in-process, encrypted,
// no FUSE). Run anywhere: go run github.com/hanzoai/sqlite3/cmd/hanzovfs-bench@latest
package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/hanzoai/sqlite3"
	_ "github.com/hanzoai/sqlite3/embed"
	"github.com/hanzoai/sqlite3/hanzovfs"
)

func bench(label, dsn string) {
	db, err := sqlite3.Open(dsn)
	if err != nil { fmt.Printf("%-26s OPEN ERR %v\n", label, err); return }
	defer db.Close()
	db.Exec(`PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;`)
	db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, email TEXT, body TEXT)`)
	const n = 20000
	t0 := time.Now()
	db.Exec("BEGIN")
	st, _, _ := db.Prepare("INSERT INTO t(email,body) VALUES(?,?)")
	for i := 0; i < n; i++ {
		st.BindText(1, fmt.Sprintf("u%d@hanzo.ai", i))
		st.BindText(2, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		st.Step(); st.Reset()
	}
	st.Close(); db.Exec("COMMIT")
	ins := float64(n) / time.Since(t0).Seconds()
	t0 = time.Now()
	sel, _, _ := db.Prepare("SELECT body FROM t WHERE id=?")
	for i := 0; i < 5000; i++ { sel.BindInt(1, 1+(i*7)%n); sel.Step(); sel.Reset() }
	sel.Close()
	fmt.Printf("%-26s insert=%9.0f rows/s   point_sel=%9.0f q/s\n", label, ins, 5000/time.Since(t0).Seconds())
}

func main() {
	fmt.Printf("hanzovfs-bench on %s/%s (%d CPU)\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	hanzovfs.Register("raw", false)
	hanzovfs.Register("enc", true)
	bench("native block-vfs (raw)", "file:/r.db?vfs=raw")
	bench("native block-vfs +AEAD", "file:/e.db?vfs=enc")
}
