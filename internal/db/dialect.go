package db

import (
	"database/sql"
	"strconv"
	"strings"
)

// DB wraps *sql.DB so we can silently rebind ? to $1,$2,... for postgres.
type DB struct {
	*sql.DB
	Driver string // "sqlite" or "postgres"
}

// Rebind rewrites ? to $1,$2,... for postgres. sqlite passes through.
func (d *DB) Rebind(query string) string {
	if d.Driver != "postgres" {
		return query
	}
	var buf strings.Builder
	buf.Grow(len(query) + 16)
	n := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			buf.WriteByte('$')
			buf.WriteString(strconv.Itoa(n))
			n++
		} else {
			buf.WriteByte(query[i])
		}
	}
	return buf.String()
}

func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(d.Rebind(query), args...)
}

func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(d.Rebind(query), args...)
}

func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(d.Rebind(query), args...)
}
