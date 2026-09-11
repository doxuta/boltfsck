package boltfsck_test

import (
	"encoding/binary"
	"hash/fnv"
	"testing"

	"github.com/doxuta/boltfsck"
)

// Hand-built database images. bbolt will not write a malformed file, so the
// paths that only a malformed file reaches — inline buckets with bad headers,
// freelists that declare impossible counts, elements whose offsets point off
// the page — are constructed here byte by byte.

type synth struct {
	pageSize int
	hwm      uint64
	root     uint64
	freelist uint64
	pages    map[uint64][]byte
}

func newSynth(pageSize int, hwm, root uint64) *synth {
	return &synth{
		pageSize: pageSize, hwm: hwm, root: root,
		freelist: 0xFFFFFFFFFFFFFFFF, // no persisted freelist unless set
		pages:    map[uint64][]byte{},
	}
}

// page returns a zeroed page buffer registered at pgid, ready to be filled.
func (s *synth) page(pgid uint64, flags, count uint16) []byte {
	b := make([]byte, s.pageSize)
	binary.LittleEndian.PutUint64(b[0:8], pgid)
	binary.LittleEndian.PutUint16(b[8:10], flags)
	binary.LittleEndian.PutUint16(b[10:12], count)
	s.pages[pgid] = b
	return b
}

func (s *synth) build() []byte {
	out := make([]byte, int(s.hwm)*s.pageSize)
	for i := 0; i < 2; i++ {
		off := i * s.pageSize
		binary.LittleEndian.PutUint64(out[off:off+8], uint64(i))
		binary.LittleEndian.PutUint16(out[off+8:off+10], 0x04) // meta page flag
		m := out[off+16 : off+16+64]
		binary.LittleEndian.PutUint32(m[0:4], 0xED0CDAED)
		binary.LittleEndian.PutUint32(m[4:8], 2)
		binary.LittleEndian.PutUint32(m[8:12], uint32(s.pageSize))
		binary.LittleEndian.PutUint64(m[16:24], s.root)
		binary.LittleEndian.PutUint64(m[32:40], s.freelist)
		binary.LittleEndian.PutUint64(m[40:48], s.hwm)
		binary.LittleEndian.PutUint64(m[48:56], uint64(2-i)) // meta 0 is newer
		h := fnv.New64a()
		_, _ = h.Write(m[:56])
		binary.LittleEndian.PutUint64(m[56:64], h.Sum64())
	}
	for pgid, p := range s.pages {
		off := int(pgid) * s.pageSize
		copy(out[off:off+s.pageSize], p)
	}
	return out
}

// putLeafElem writes leaf element i and its key/value payload. pos is relative
// to the element's own start, which is the part of the format that is easiest
// to get wrong.
func putLeafElem(page []byte, i int, flags uint32, key, val []byte, payloadOff int) {
	elemOff := 16 + i*16
	pos := payloadOff - elemOff
	binary.LittleEndian.PutUint32(page[elemOff+0:], flags)
	binary.LittleEndian.PutUint32(page[elemOff+4:], uint32(pos))
	binary.LittleEndian.PutUint32(page[elemOff+8:], uint32(len(key)))
	binary.LittleEndian.PutUint32(page[elemOff+12:], uint32(len(val)))
	copy(page[payloadOff:], key)
	copy(page[payloadOff+len(key):], val)
}

func checkSynth(t *testing.T, s *synth) *boltfsck.Report {
	t.Helper()
	rep := boltfsck.CheckBytes(s.build(), boltfsck.Options{})
	if rep == nil {
		t.Fatal("nil report")
	}
	return rep
}

func wantProblem(t *testing.T, rep *boltfsck.Report, code boltfsck.ProblemCode) {
	t.Helper()
	if rep.Count(code) == 0 {
		t.Fatalf("want a %s problem, got:\n%s", code, rep)
	}
}

// TestSynthHealthyBaseline proves the builder itself produces a file boltfsck
// accepts. Without this, every test below would pass on a builder that emits
// garbage.
func TestSynthHealthyBaseline(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1) // leaf with one ordinary key
	putLeafElem(p, 0, 0, []byte("k"), []byte("v"), 16+16)
	rep := checkSynth(t, s)
	if !rep.OK() {
		t.Fatalf("synthetic healthy file reported as damaged:\n%s", rep)
	}
}

func TestBucketEntryValueTooShort(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1)
	// Flagged as a bucket, but the value is 8 bytes and a bucket header is 16.
	putLeafElem(p, 0, 0x01, []byte("b"), make([]byte, 8), 16+16)
	wantProblem(t, checkSynth(t, s), boltfsck.ShortValue)
}

func TestInlineBucketWithWrongPageFlags(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1)
	val := make([]byte, 16+16)                      // bucket header + an inline page header
	binary.LittleEndian.PutUint64(val[0:8], 0)      // root 0 means inline
	binary.LittleEndian.PutUint16(val[16+8:], 0x01) // inline page claims to be a branch
	putLeafElem(p, 0, 0x01, []byte("b"), val, 16+16)
	wantProblem(t, checkSynth(t, s), boltfsck.BadPageFlags)
}

func TestInlineBucketCountOverflow(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1)
	val := make([]byte, 16+16)
	binary.LittleEndian.PutUint64(val[0:8], 0)
	binary.LittleEndian.PutUint16(val[16+8:], 0x02)  // leaf
	binary.LittleEndian.PutUint16(val[16+10:], 4000) // more entries than the value can hold
	putLeafElem(p, 0, 0x01, []byte("b"), val, 16+16)
	wantProblem(t, checkSynth(t, s), boltfsck.CountOverflow)
}

func TestInlineBucketElementOutOfBounds(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1)
	val := make([]byte, 16+16+16)
	binary.LittleEndian.PutUint64(val[0:8], 0)
	binary.LittleEndian.PutUint16(val[16+8:], 0x02)
	binary.LittleEndian.PutUint16(val[16+10:], 1)
	// One inline entry whose key runs off the end of the inline page.
	binary.LittleEndian.PutUint32(val[16+16+4:], 8)        // pos
	binary.LittleEndian.PutUint32(val[16+16+8:], 0xFFFFFF) // ksize
	putLeafElem(p, 0, 0x01, []byte("b"), val, 16+16)
	wantProblem(t, checkSynth(t, s), boltfsck.ElementOutOfBounds)
}

func TestLeafElementRunsOffThePage(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 1)
	putLeafElem(p, 0, 0, []byte("k"), []byte("v"), 16+16)
	// Rewrite vsize so key+value extends past the page.
	binary.LittleEndian.PutUint32(p[16+12:], 0xFFFFFFF)
	wantProblem(t, checkSynth(t, s), boltfsck.ElementOutOfBounds)
}

func TestBranchElementRunsOffThePage(t *testing.T) {
	s := newSynth(4096, 5, 2)
	br := s.page(2, 0x01, 1)
	binary.LittleEndian.PutUint32(br[16+0:], 0xFFFFFF0) // pos
	binary.LittleEndian.PutUint32(br[16+4:], 4)         // ksize
	binary.LittleEndian.PutUint64(br[16+8:], 3)         // child
	leaf := s.page(3, 0x02, 0)
	_ = leaf
	wantProblem(t, checkSynth(t, s), boltfsck.ElementOutOfBounds)
}

func TestFreelistWrongPageType(t *testing.T) {
	s := newSynth(4096, 5, 2)
	s.freelist = 3
	s.page(2, 0x02, 0)
	s.page(3, 0x02, 0) // a leaf page where the freelist should be
	wantProblem(t, checkSynth(t, s), boltfsck.BadPageFlags)
}

func TestFreelistCountDoesNotFit(t *testing.T) {
	s := newSynth(4096, 5, 2)
	s.freelist = 3
	s.page(2, 0x02, 0)
	fl := s.page(3, 0x10, 0xFFFF) // the overflow form
	// The real count lives in the first pgid slot, and this one cannot fit.
	binary.LittleEndian.PutUint64(fl[16:24], 1<<40)
	wantProblem(t, checkSynth(t, s), boltfsck.FreelistInvalid)
}

func TestFreelistEntryPastHighWaterMark(t *testing.T) {
	s := newSynth(4096, 5, 2)
	s.freelist = 3
	s.page(2, 0x02, 0)
	fl := s.page(3, 0x10, 1)
	binary.LittleEndian.PutUint64(fl[16:24], 99999)
	wantProblem(t, checkSynth(t, s), boltfsck.OutOfBounds)
}

// TestFreelistOverlapsTheTree is the corruption that silently loses data:
// a page that is both reachable and marked reusable will be handed out and
// overwritten while it still holds live keys.
func TestFreelistOverlapsTheTree(t *testing.T) {
	s := newSynth(4096, 6, 2)
	s.freelist = 3
	br := s.page(2, 0x01, 1)
	binary.LittleEndian.PutUint32(br[16+0:], 16) // pos
	binary.LittleEndian.PutUint32(br[16+4:], 1)  // ksize
	binary.LittleEndian.PutUint64(br[16+8:], 4)  // child -> page 4
	s.page(4, 0x02, 0)
	fl := s.page(3, 0x10, 1)
	binary.LittleEndian.PutUint64(fl[16:24], 4) // page 4 is also on the freelist
	wantProblem(t, checkSynth(t, s), boltfsck.FreelistOverlap)
}

func TestFreelistPagePastHighWaterMark(t *testing.T) {
	s := newSynth(4096, 5, 2)
	s.freelist = 4000
	s.page(2, 0x02, 0)
	wantProblem(t, checkSynth(t, s), boltfsck.OutOfBounds)
}

// TestOverflowFieldIsNotAnAllocationBomb: a page claiming four billion
// overflow pages must not make the checker try to allocate them.
func TestOverflowFieldIsNotAnAllocationBomb(t *testing.T) {
	s := newSynth(4096, 4, 2)
	p := s.page(2, 0x02, 0)
	binary.LittleEndian.PutUint32(p[12:16], 0xFFFFFFFF)
	rep := checkSynth(t, s)
	if rep.OK() {
		t.Fatalf("absurd overflow accepted:\n%s", rep)
	}
	wantProblem(t, rep, boltfsck.CountOverflow)
}

// TestProblemStringIncludesTheStack checks the reference chain is rendered,
// since that is what makes a cycle report actionable.
func TestProblemStringIncludesTheStack(t *testing.T) {
	s := newSynth(4096, 6, 2)
	br := s.page(2, 0x01, 1)
	binary.LittleEndian.PutUint32(br[16+0:], 16)
	binary.LittleEndian.PutUint32(br[16+4:], 1)
	binary.LittleEndian.PutUint64(br[16+8:], 2) // child points back at itself
	rep := checkSynth(t, s)
	wantProblem(t, rep, boltfsck.CycleRef)
	found := false
	for _, p := range rep.Problems {
		if p.Code == boltfsck.CycleRef && len(p.Stack) > 0 {
			found = true
			if !contains(p.String(), "via") {
				t.Fatalf("cycle problem does not render its stack: %s", p)
			}
		}
	}
	if !found {
		t.Fatalf("no cycle problem carried a reference stack:\n%s", rep)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
