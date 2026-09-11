// Package boltfsck inspects a bbolt database file without opening it with
// bbolt.
//
// When a bbolt file is corrupt, the usual tools are of no help: bbolt's own
// Tx.Check reaches the damaged pages through the same mmap-and-cast loader
// that the damage defeats, and every third-party browser imports bbolt and
// inherits that loader. A page id inside the declared high-water mark but past
// the end of the file is an unrecoverable fault, not an error value, because
// the address is computed before anything checks whether it is mapped.
//
// boltfsck reads the file with ReadAt into ordinary heap buffers and decodes
// every field with encoding/binary. It never maps the file and never uses
// unsafe. Bounds are checked before each read, the page walk carries a visited
// set so cyclic references terminate, and the whole walk runs under a work
// budget. The result is a Report, always — a file that cannot be parsed at all
// produces a report saying so rather than a crash.
//
// It diagnoses; it does not repair. There is no fix or salvage mode, which is
// what keeps the tool small enough to trust.
//
// Built with an AI-agent workflow; see README.md.
package boltfsck

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// Options controls a check.
type Options struct {
	// PageSize overrides the page size instead of reading it from a meta page.
	// Zero means discover it, which is almost always what you want: bbolt
	// writes files with the page size of the machine that created them
	// (4096 on most Linux, 16384 on Apple Silicon), so the inspecting machine
	// frequently differs from the writing one.
	PageSize int

	// Budget caps the number of pages the walk will read. Zero selects a
	// default of ten times the high-water mark, with a floor of 1024. A walk
	// that hits its budget sets Report.Incomplete.
	Budget int
}

// source is the minimal view of a file the checker needs.
type source interface {
	io.ReaderAt
	Size() int64
}

type fileSource struct {
	f    *os.File
	size int64
}

func (s *fileSource) ReadAt(p []byte, off int64) (int, error) { return s.f.ReadAt(p, off) }
func (s *fileSource) Size() int64                             { return s.size }

type bytesSource struct{ b []byte }

func (s *bytesSource) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(s.b).ReadAt(p, off)
}
func (s *bytesSource) Size() int64 { return int64(len(s.b)) }

// DB is an open handle on a database file being inspected. It is read-only and
// never writes to the file.
type DB struct {
	src *fileSource
}

// Open opens a database file for inspection. It does not validate the file;
// even a file bbolt refuses to open can be inspected, which is the point.
func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() {
		f.Close()
		return nil, fmt.Errorf("boltfsck: %s is a directory", path)
	}
	return &DB{src: &fileSource{f: f, size: fi.Size()}}, nil
}

// Close releases the file handle.
func (db *DB) Close() error { return db.src.f.Close() }

// Check walks the database and returns everything it found. It never returns
// nil and never panics on malformed input.
func (db *DB) Check(opts Options) *Report { return check(db.src, opts) }

// CheckBytes checks an in-memory image of a database file. It is the same
// checker Check uses, exposed for callers that already hold the bytes — and
// for fuzzing.
func CheckBytes(b []byte, opts Options) *Report { return check(&bytesSource{b: b}, opts) }
