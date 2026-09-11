package boltfsck_test

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/doxuta/boltfsck"
)

// TestCheckedInFixtures pins the exact output of the files in testdata/, which
// are the files the README quotes and the files bbolt was measured against.
func TestCheckedInFixtures(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		db, err := boltfsck.Open("testdata/healthy.db")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rep := db.Check(boltfsck.Options{})
		if !rep.OK() {
			t.Fatalf("checked-in healthy fixture reported as damaged:\n%s", rep)
		}
		if rep.PageSize != 4096 || rep.HighWater != 45 {
			t.Fatalf("fixture drifted: pageSize %d, hwm %d; regenerate testdata and the README numbers",
				rep.PageSize, rep.HighWater)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		db, err := boltfsck.Open("testdata/truncated.db")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rep := db.Check(boltfsck.Options{})
		if rep.OK() {
			t.Fatalf("truncated fixture reported as healthy:\n%s", rep)
		}
		if got := len(rep.Problems); got != 3 {
			t.Fatalf("want 3 problems (the number quoted in the README), got %d:\n%s", got, rep)
		}
		if rep.Count(boltfsck.Truncated) != 3 {
			t.Fatalf("want all 3 problems to be truncation:\n%s", rep)
		}
		if rep.Incomplete {
			t.Fatalf("the walk should have completed, not been curtailed:\n%s", rep)
		}
	})
}

// TestTruncatedFixtureIsDeterministic is the claim the README rests on. bbolt
// dies on this same file with SIGSEGV or SIGBUS, and which signal it gets
// varies between runs; boltfsck must produce byte-identical findings every
// time, because a diagnostic tool whose answer moves is not a diagnosis.
func TestTruncatedFixtureIsDeterministic(t *testing.T) {
	b := readFile(t, "testdata/truncated.db")
	first := boltfsck.CheckBytes(b, boltfsck.Options{}).String()
	for i := 0; i < 200; i++ {
		if got := boltfsck.CheckBytes(b, boltfsck.Options{}).String(); got != first {
			t.Fatalf("run %d differed:\nfirst:\n%s\ngot:\n%s", i, first, got)
		}
	}
}

// TestLibraryDoesNotImportBbolt is the discipline this package exists to keep.
// If the library ever imports bbolt, it inherits the mmap-and-cast loader that
// faults on exactly the files it is supposed to diagnose, and the whole thing
// is pointless. bbolt may appear in _test.go files only.
func TestLibraryDoesNotImportBbolt(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := pkgs["boltfsck"]
	if !ok {
		t.Fatal("package boltfsck not found in the current directory")
	}
	checked := 0
	{
		for file, f := range pkg.Files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			checked++
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "bbolt") {
					t.Errorf("%s imports %s; the library must decode pages itself",
						file, imp.Path.Value)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test files were inspected; this guard is not actually running")
	}
}
