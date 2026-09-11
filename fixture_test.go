package boltfsck_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bbolt "go.etcd.io/bbolt"
)

// bbolt is a TEST-ONLY dependency. The library itself must never import it:
// bbolt's loader is the component that fails on the files boltfsck inspects.
// Here it is used for the two things it is good at — writing a known-good
// database, and acting as the oracle that says a healthy file is healthy.

// writeDB creates a database with the shapes that matter: enough keys to force
// branch pages, a value large enough to need overflow pages, and a small nested
// bucket that bbolt stores inline instead of on its own page.
func writeDB(t testing.TB, pageSize int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{PageSize: pageSize})
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		users, err := tx.CreateBucket([]byte("users"))
		if err != nil {
			return err
		}
		for i := 0; i < 4000; i++ {
			k := []byte(fmt.Sprintf("user-%06d", i))
			v := []byte(fmt.Sprintf("value-%06d-padding-to-make-pages-split", i))
			if err := users.Put(k, v); err != nil {
				return err
			}
		}
		big, err := tx.CreateBucket([]byte("big"))
		if err != nil {
			return err
		}
		// Three pages' worth in one value forces overflow pages.
		if err := big.Put([]byte("blob"), make([]byte, pageSize*3)); err != nil {
			return err
		}
		tiny, err := tx.CreateBucket([]byte("tiny"))
		if err != nil {
			return err
		}
		// A small sub-bucket is inlined into its parent's leaf value.
		sub, err := tiny.CreateBucket([]byte("inlined"))
		if err != nil {
			return err
		}
		return sub.Put([]byte("k"), []byte("v"))
	})
	if err != nil {
		t.Fatalf("populating: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// bboltCheckErrors runs bbolt's own consistency check. Used only on files that
// are expected to be healthy — running it on a corrupt file is precisely what
// hangs or faults, which is why boltfsck exists.
func bboltCheckErrors(t testing.TB, path string) []error {
	t.Helper()
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("bbolt.Open for check: %v", err)
	}
	defer db.Close()
	var errs []error
	err = db.View(func(tx *bbolt.Tx) error {
		for e := range tx.Check() {
			errs = append(errs, e)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("bbolt View: %v", err)
	}
	return errs
}

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return b
}

// pageOffset returns the byte offset of a page. Page size is read from meta 0
// rather than assumed, because bbolt writes files with the page size of the
// machine that created them.
func metaPageSize(b []byte) int {
	return int(binary.LittleEndian.Uint32(b[16+8 : 16+12]))
}

// metaHighWater reads the page count meta 0 declares.
func metaHighWater(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b[16+40 : 16+48])
}

func pageFlags(b []byte, ps int, pgid int) uint16 {
	return binary.LittleEndian.Uint16(b[pgid*ps+8 : pgid*ps+10])
}

func setPageFlags(b []byte, ps, pgid int, flags uint16) {
	binary.LittleEndian.PutUint16(b[pgid*ps+8:pgid*ps+10], flags)
}

func pageCount(b []byte, ps, pgid int) uint16 {
	return binary.LittleEndian.Uint16(b[pgid*ps+10 : pgid*ps+12])
}

func setPageCount(b []byte, ps, pgid int, count uint16) {
	binary.LittleEndian.PutUint16(b[pgid*ps+10:pgid*ps+12], count)
}

// firstBranchPage finds a branch page to corrupt. Branch pages are where the
// interesting damage lives, because they are what the walk follows.
func firstBranchPage(t testing.TB, b []byte, ps int) int {
	t.Helper()
	n := len(b) / ps
	for pgid := 2; pgid < n; pgid++ {
		if pageFlags(b, ps, pgid) == 0x01 && pageCount(b, ps, pgid) > 0 {
			return pgid
		}
	}
	t.Fatalf("no branch page in the fixture; the generator needs more keys")
	return 0
}

// setBranchChild rewrites the page id that branch element i points at.
func setBranchChild(b []byte, ps, pgid, i int, child uint64) {
	off := pgid*ps + 16 + i*16 + 8
	binary.LittleEndian.PutUint64(b[off:off+8], child)
}

func writeTemp(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}
