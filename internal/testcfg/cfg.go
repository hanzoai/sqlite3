package testcfg

import (
	"context"

	"github.com/hanzoai/sqlite3"
	"github.com/hanzoai/sqlite3/internal/testenv"
)

func Context(t testenv.Context) context.Context {
	return sqlite3.WithMaxMemory(t.Context(), 32*1024*1024)
}
