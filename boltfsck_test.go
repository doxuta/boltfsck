package boltfsck_test

import (
	"encoding/binary"
	"hash/fnv"
	"os"
	"testing"

	"github.com/doxuta/boltfsck"
)

// TestHealthyAgreesWithBbolt is the differential test: on a file bbolt itself
// pronounces healthy, boltfsck must find nothing. Without this, a checker that
// reports everything as broken would pass every corruption test below.
func TestHealthyAgreesWithBbolt(t *testing.T) {
	path := writeDB(t, 4096)

	if errs := bboltCheckErrors(t, path); len(errs) != 0 {
		t.Fatalf("fixture is not healthy according to bbolt: %v", errs)
	}

	db, err := boltfsck.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	rep := db.Check(boltfsck.Options{})

	if !rep.OK() {
		t.Fatalf("healthy file reported as damaged:\n%s", rep)
	}
	if rep.PageSize != 4096 {
		t.Errorf("PageSize = %d, want 4096", rep.PageSize)
	}
	if rep.PagesVisited < 10 {
		t.Errorf("PagesVisited = %d; the walk did not descend into the tree", rep.PagesVisited)
	}
	if rep.MetaUsed != 0 && rep.MetaUsed != 1 {
		t.Errorf("MetaUsed = %d, want 0 or 1", rep.MetaUsed)
	}
}

// TestInlineBucketIsWalked pins the trap that makes a from-scratch reader walk
// one page instead of the whole database: a leaf value flagged as a bucket
// whose root page id is 0 is an INLINE bucket, not a reference to page 0.
func TestInlineBucketIsWalked(t *testing.T) {
	path := writeDB(t, 4096)
	db, err := boltfsck.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	rep := db.Check(boltfsck.Options{})

	if !rep.OK() {
		t.Fatalf("healthy file reported as damaged:\n%s", rep)
	}
	// If an inline bucket were mistaken for a reference to page 0, the walk
	// would follow a meta page from inside the tree and report it.
	if n := rep.Count(boltfsck.MetaPageInTree); n != 0 {
		t.Fatalf("inline bucket was followed as a page reference: %d flag problems\n%s", n, rep)
	}
}

// TestPageSizeIsReadFromMetaNotAssumed checks a file written with a page size
// that differs from this machine's. bbolt defaults to os.Getpagesize(), which
// is 4096 on most Linux and 16384 on Apple Silicon, so a file is routinely
// inspected on a machine that would guess wrong.
func TestPageSizeIsReadFromMetaNotAssumed(t *testing.T) {
	for _, ps := range []int{4096, 8192, 16384} {
		t.Run(itoa(ps), func(t *testing.T) {
			path := writeDB(t, ps)
			db, err := boltfsck.Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer db.Close()
			rep := db.Check(boltfsck.Options{})
			if rep.PageSize != ps {
				t.Fatalf("PageSize = %d, want %d", rep.PageSize, ps)
			}
			if !rep.OK() {
				t.Fatalf("healthy %d-byte-page file reported as damaged:\n%s", ps, rep)
			}
		})
	}
}

// TestSelfCycleTerminates is the case that hangs bbolt's own check: a branch
// page whose child pointer is itself. The reachability walk descends forever.
// Here it must terminate with a named problem.
func TestSelfCycleTerminates(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	ps := metaPageSize(b)
	br := firstBranchPage(t, b, ps)
	setBranchChild(b, ps, br, 0, uint64(br))

	rep := boltfsck.CheckBytes(b, boltfsck.Options{})

	if rep.OK() {
		t.Fatalf("self-cycle not detected:\n%s", rep)
	}
	if rep.Count(boltfsck.CycleRef) == 0 {
		t.Fatalf("want a cycle_ref problem, got:\n%s", rep)
	}
	if rep.PagesVisited > rep.Budget {
		t.Fatalf("walk exceeded its budget: visited %d, budget %d", rep.PagesVisited, rep.Budget)
	}
}

// TestTruncatedFile is the case bbolt cannot survive at all: a page inside the
// declared high-water mark that lies past the end of the file. bbolt validates
// the id against the meta page and then reads unmapped memory, which is a
// fault that recover cannot catch.
func TestTruncatedFile(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	ps := metaPageSize(b)
	full := len(b)
	b = b[:full/2] // keep the meta pages, lose the tail

	rep := boltfsck.CheckBytes(b, boltfsck.Options{})

	if rep.OK() {
		t.Fatalf("truncation not detected:\n%s", rep)
	}
	if rep.Count(boltfsck.Truncated) == 0 {
		t.Fatalf("want a truncated problem, got:\n%s", rep)
	}
	if rep.HighWater <= uint64(len(b)/ps) {
		t.Fatalf("fixture does not actually test truncation: hwm %d, pages present %d",
			rep.HighWater, len(b)/ps)
	}
}

// TestMeta0DamagedFallsBackToMeta1 mirrors what bbolt does. A database whose
// newest meta write was torn is still readable from the older one, and a
// checker that refuses to open it is less useful than the library it replaces.
func TestMeta0DamagedFallsBackToMeta1(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	b[16] ^= 0xFF // corrupt meta 0's magic

	rep := boltfsck.CheckBytes(b, boltfsck.Options{})

	if rep.MetaUsed != 1 {
		t.Fatalf("MetaUsed = %d, want 1 (fallback to the older meta page)\n%s", rep.MetaUsed, rep)
	}
	if rep.Count(boltfsck.BadMagic) != 1 {
		t.Fatalf("want exactly one bad_magic problem, got:\n%s", rep)
	}
	// Meta 1 holds the previous transaction, so its tree is an older and
	// smaller — but entirely valid — snapshot. The point is that the walk ran
	// at all, and that the torn meta page is the only thing reported.
	if rep.PagesVisited < 1 {
		t.Fatalf("fell back to meta 1 but walked nothing\n%s", rep)
	}
	if len(rep.Problems) != 1 {
		t.Fatalf("want only the bad_magic problem, got:\n%s", rep)
	}
	if rep.Incomplete {
		t.Fatalf("walk did not complete:\n%s", rep)
	}
}

// TestMetaWithBadChecksumIsNotUsed pins meta SELECTION, not merely meta
// reporting. Magic and version are left intact and only a checksummed field is
// disturbed, so the sole thing that can reject meta 0 is the checksum itself.
// A checker that reports the bad checksum but still walks from the torn meta
// page produces confident, wrong answers.
func TestMetaWithBadChecksumIsNotUsed(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	// Meta 0's root-bucket page id sits at meta offset 16, inside the
	// checksummed range [0,56).
	b[16+16] ^= 0x0F

	rep := boltfsck.CheckBytes(b, boltfsck.Options{})

	if rep.Count(boltfsck.BadChecksum) == 0 {
		t.Fatalf("want a bad_checksum problem, got:\n%s", rep)
	}
	if rep.MetaUsed != 1 {
		t.Fatalf("MetaUsed = %d; a meta page whose checksum fails must not be walked from\n%s",
			rep.MetaUsed, rep)
	}
}

// TestBothMetasDamaged must produce a report, not a crash and not a hang.
func TestBothMetasDamaged(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	ps := metaPageSize(b)
	b[16] ^= 0xFF
	b[ps+16] ^= 0xFF

	rep := boltfsck.CheckBytes(b, boltfsck.Options{})

	if rep.MetaUsed != -1 {
		t.Fatalf("MetaUsed = %d, want -1", rep.MetaUsed)
	}
	if rep.Count(boltfsck.NoValidMeta) == 0 {
		t.Fatalf("want no_valid_meta, got:\n%s", rep)
	}
}

// TestCorruptions walks a table of single-defect mutations. Each must be
// detected, named with the right code, and must terminate.
func TestCorruptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t testing.TB, b []byte, ps int) []byte
		want    boltfsck.ProblemCode
		wantMsg string
	}{
		{
			name: "child past high-water mark",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				setBranchChild(b, ps, firstBranchPage(t, b, ps), 0, 1<<40)
				return b
			},
			want: boltfsck.OutOfBounds,
		},
		{
			name: "child is a meta page",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				setBranchChild(b, ps, firstBranchPage(t, b, ps), 0, 0)
				return b
			},
			want: boltfsck.MetaPageInTree,
		},
		{
			name: "branch element count overflows the page",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				setPageCount(b, ps, firstBranchPage(t, b, ps), 60000)
				return b
			},
			want: boltfsck.CountOverflow,
		},
		{
			name: "page type flags are nonsense",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				setPageFlags(b, ps, firstBranchPage(t, b, ps), 0x37)
				return b
			},
			want: boltfsck.BadPageFlags,
		},
		{
			name: "page header disagrees about its own id",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				p := firstBranchPage(t, b, ps)
				binary.LittleEndian.PutUint64(b[p*ps:p*ps+8], 999999)
				return b
			},
			want: boltfsck.PageIDMismatch,
		},
		{
			name: "meta checksum does not match its contents",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				// Flip a byte in meta 0's body and leave the checksum alone.
				b[16+20] ^= 0x01
				return b
			},
			want: boltfsck.BadChecksum,
		},
		{
			name: "two branch entries point at the same page",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				p := firstBranchPage(t, b, ps)
				if pageCount(b, ps, p) < 2 {
					t.Skip("branch page has fewer than two entries")
				}
				first := binary.LittleEndian.Uint64(b[p*ps+16+8 : p*ps+16+16])
				setBranchChild(b, ps, p, 1, first)
				return b
			},
			want: boltfsck.SharedPage,
		},
		{
			name: "truncated mid-page",
			mutate: func(t testing.TB, b []byte, ps int) []byte {
				// Cut inside the high-water mark, not into the slack bbolt
				// preallocates past it — truncating the slack is invisible by
				// design, and a test that did that would prove nothing.
				hwm := int(metaHighWater(b))
				return b[:hwm*ps-ps/2]
			},
			want: boltfsck.Truncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := readFile(t, writeDB(t, 4096))
			ps := metaPageSize(b)
			b = tt.mutate(t, b, ps)

			rep := boltfsck.CheckBytes(b, boltfsck.Options{})

			if rep.OK() {
				t.Fatalf("corruption not detected:\n%s", rep)
			}
			if rep.Count(tt.want) == 0 {
				t.Fatalf("want a %s problem, got:\n%s", tt.want, rep)
			}
			if rep.PagesVisited > rep.Budget {
				t.Fatalf("walk exceeded its budget: %d > %d", rep.PagesVisited, rep.Budget)
			}
		})
	}
}

// TestBudgetStopsAndSaysSo checks that a curtailed walk never reads as clean.
func TestBudgetStopsAndSaysSo(t *testing.T) {
	path := writeDB(t, 4096)
	db, err := boltfsck.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rep := db.Check(boltfsck.Options{Budget: 5})

	if !rep.Incomplete {
		t.Fatalf("Incomplete = false after a budget of 5\n%s", rep)
	}
	if rep.OK() {
		t.Fatal("OK() is true on an incomplete walk; a partial check must never read as clean")
	}
	if rep.PagesVisited > 5 {
		t.Fatalf("visited %d pages on a budget of 5", rep.PagesVisited)
	}
}

// TestNotADatabase must report rather than crash.
func TestNotADatabase(t *testing.T) {
	rep := boltfsck.CheckBytes([]byte("this is not a bolt database, not even close"), boltfsck.Options{})
	if rep.OK() {
		t.Fatal("a text file was reported as a healthy database")
	}
	if rep.Count(boltfsck.NoValidMeta) == 0 {
		t.Fatalf("want no_valid_meta, got:\n%s", rep)
	}
}

func TestEmptyAndTinyInputs(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 4095} {
		rep := boltfsck.CheckBytes(make([]byte, n), boltfsck.Options{})
		if rep == nil {
			t.Fatalf("nil report for a %d-byte input", n)
		}
		if rep.OK() {
			t.Fatalf("a %d-byte zero file was reported healthy", n)
		}
	}
}

// TestMetaChecksumMatchesBbolt pins the checksum algorithm itself: FNV-1a 64
// over the meta structure up to but excluding the checksum field. If this
// drifts, every healthy file starts reporting as corrupt.
func TestMetaChecksumMatchesBbolt(t *testing.T) {
	b := readFile(t, writeDB(t, 4096))
	meta0 := b[16 : 16+64]
	h := fnv.New64a()
	if _, err := h.Write(meta0[:56]); err != nil {
		t.Fatal(err)
	}
	want := binary.LittleEndian.Uint64(meta0[56:64])
	if h.Sum64() != want {
		t.Fatalf("checksum over meta bytes [0,56) = %#016x, file stores %#016x", h.Sum64(), want)
	}
	// And boltfsck must agree, i.e. report no checksum problem.
	rep := boltfsck.CheckBytes(b, boltfsck.Options{})
	if rep.Count(boltfsck.BadChecksum) != 0 {
		t.Fatalf("boltfsck disagrees with the file's own checksum:\n%s", rep)
	}
}

// TestOpenMissingFile checks the error path.
func TestOpenMissingFile(t *testing.T) {
	if _, err := boltfsck.Open("/nonexistent/definitely/not/here.db"); err == nil {
		t.Fatal("Open on a missing file returned no error")
	}
	dir := t.TempDir()
	if _, err := boltfsck.Open(dir); err == nil {
		t.Fatal("Open on a directory returned no error")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
