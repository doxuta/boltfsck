package boltfsck_test

import (
	"testing"

	"github.com/doxuta/boltfsck"
)

// FuzzCheckBytes is the strongest available statement of "crash-safe": for any
// input at all, the checker must return a report rather than panic, and must
// terminate within its budget.
func FuzzCheckBytes(f *testing.F) {
	healthy := readFile(f, writeDB(f, 4096))
	f.Add(healthy)
	f.Add(healthy[:len(healthy)/2])
	f.Add(healthy[:64])
	f.Add([]byte{})
	f.Add([]byte("not a database"))

	// A copy with both meta pages destroyed, so the fuzzer starts from an
	// input that already exercises the no-valid-meta path.
	broken := append([]byte(nil), healthy...)
	if len(broken) > 4096+20 {
		broken[16] ^= 0xFF
		broken[4096+16] ^= 0xFF
	}
	f.Add(broken)

	f.Fuzz(func(t *testing.T, b []byte) {
		rep := boltfsck.CheckBytes(b, boltfsck.Options{Budget: 512})
		if rep == nil {
			t.Fatal("nil report")
		}
		if rep.PagesVisited > rep.Budget && rep.Budget > 0 {
			t.Fatalf("visited %d pages on a budget of %d", rep.PagesVisited, rep.Budget)
		}
		if len(rep.Problems) > 10001 {
			t.Fatalf("problem list grew to %d entries", len(rep.Problems))
		}
		// Rendering must be total too; a report you cannot print is not a
		// report.
		_ = rep.String()
	})
}
