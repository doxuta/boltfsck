package boltfsck

import "encoding/binary"

// On-disk layout constants, mirrored by hand from go.etcd.io/bbolt.
//
// They are duplicated here deliberately. boltfsck must never import bbolt,
// because bbolt's page loader is the component that fails on the files
// boltfsck exists to inspect: it maps the file and reinterprets the mapping
// with unsafe.Pointer, so a page that is inside the declared high-water mark
// but outside the mapping faults in a way recover cannot catch.
const (
	pageHeaderSize = 16 // id uint64, flags uint16, count uint16, overflow uint32
	metaSize       = 64
	metaSumOffset  = 56 // checksum covers meta bytes [0, 56)
	branchElemSize = 16 // pos uint32, ksize uint32, pgid uint64
	leafElemSize   = 16 // flags uint32, pos uint32, ksize uint32, vsize uint32
	inBucketSize   = 16 // root uint64, sequence uint64

	branchPageFlag   = 0x01
	leafPageFlag     = 0x02
	metaPageFlag     = 0x04
	freelistPageFlag = 0x10

	bucketLeafFlag = 0x01

	boltMagic   uint32 = 0xED0CDAED
	boltVersion uint32 = 2

	pgidNoFreelist uint64 = 0xFFFFFFFFFFFFFFFF

	// A freelist page whose count field reads 0xFFFF stores the real count in
	// the first pgid slot, which shifts every id that follows by one slot.
	freelistCountOverflow = 0xFFFF
)

// candidatePageSizes are tried, in order, when the meta page that records the
// page size is itself unreadable. bbolt defaults to os.Getpagesize(), which is
// 4096 on most Linux and 16384 on Apple Silicon, so a file is routinely
// inspected on a machine whose native page size differs from the one that
// wrote it.
var candidatePageSizes = []int{4096, 16384, 8192, 32768, 65536}

// pageHeader is the 16-byte header every bbolt page starts with.
type pageHeader struct {
	ID       uint64
	Flags    uint16
	Count    uint16
	Overflow uint32
}

func decodePageHeader(b []byte) (pageHeader, bool) {
	if len(b) < pageHeaderSize {
		return pageHeader{}, false
	}
	return pageHeader{
		ID:       binary.LittleEndian.Uint64(b[0:8]),
		Flags:    binary.LittleEndian.Uint16(b[8:10]),
		Count:    binary.LittleEndian.Uint16(b[10:12]),
		Overflow: binary.LittleEndian.Uint32(b[12:16]),
	}, true
}

// typ names the page type for a report. Unknown flag combinations are rendered
// rather than rejected, because naming the bad value is the diagnosis.
func (h pageHeader) typ() string {
	switch h.Flags {
	case branchPageFlag:
		return "branch"
	case leafPageFlag:
		return "leaf"
	case metaPageFlag:
		return "meta"
	case freelistPageFlag:
		return "freelist"
	default:
		return "unknown"
	}
}

// validFlags reports whether exactly one known page-type flag is set.
func (h pageHeader) validFlags() bool {
	switch h.Flags {
	case branchPageFlag, leafPageFlag, metaPageFlag, freelistPageFlag:
		return true
	}
	return false
}

// branchElem is one entry on a branch page.
type branchElem struct {
	Pos   uint32
	Ksize uint32
	Pgid  uint64
}

// leafElem is one entry on a leaf page.
type leafElem struct {
	Flags uint32
	Pos   uint32
	Ksize uint32
	Vsize uint32
}

func (e leafElem) isBucket() bool { return e.Flags&bucketLeafFlag != 0 }

// decodeBranchElem reads element i out of page, where page is the whole
// (overflow-inclusive) page span. ok is false when the element header itself
// does not fit.
func decodeBranchElem(page []byte, i int) (branchElem, bool) {
	off := pageHeaderSize + i*branchElemSize
	if off < 0 || off+branchElemSize > len(page) {
		return branchElem{}, false
	}
	b := page[off : off+branchElemSize]
	return branchElem{
		Pos:   binary.LittleEndian.Uint32(b[0:4]),
		Ksize: binary.LittleEndian.Uint32(b[4:8]),
		Pgid:  binary.LittleEndian.Uint64(b[8:16]),
	}, true
}

func decodeLeafElem(page []byte, i int) (leafElem, bool) {
	off := pageHeaderSize + i*leafElemSize
	if off < 0 || off+leafElemSize > len(page) {
		return leafElem{}, false
	}
	b := page[off : off+leafElemSize]
	return leafElem{
		Flags: binary.LittleEndian.Uint32(b[0:4]),
		Pos:   binary.LittleEndian.Uint32(b[4:8]),
		Ksize: binary.LittleEndian.Uint32(b[8:12]),
		Vsize: binary.LittleEndian.Uint32(b[12:16]),
	}, true
}

// elemSpan returns the byte range a key (and optionally a value) occupies.
//
// pos is relative to the START OF THE ELEMENT, not the start of the page. This
// is the single easiest thing to get wrong when reimplementing the format from
// the struct definitions, because bbolt computes it with pointer arithmetic
// from the element address.
func elemSpan(elemOff int, pos, size1, size2 uint32) (start, end int, ok bool) {
	// Do the arithmetic in uint64 so a hostile 0xFFFFFFFF cannot wrap.
	s := uint64(elemOff) + uint64(pos)
	e := s + uint64(size1) + uint64(size2)
	if e > uint64(1<<62) {
		return 0, 0, false
	}
	return int(s), int(e), true
}

// freelistIDs decodes the page ids held on a freelist page. It returns the
// declared count separately so an impossible count can be reported even when
// the ids cannot be read.
func freelistIDs(page []byte, h pageHeader) (ids []uint64, declared uint64, ok bool) {
	if len(page) < pageHeaderSize {
		return nil, 0, false
	}
	idx := 0
	count := uint64(h.Count)
	if h.Count == freelistCountOverflow {
		if pageHeaderSize+8 > len(page) {
			return nil, 0, false
		}
		count = binary.LittleEndian.Uint64(page[pageHeaderSize : pageHeaderSize+8])
		idx = 1
	}
	declared = count
	need := (uint64(idx) + count) * 8
	if need > uint64(len(page)-pageHeaderSize) {
		return nil, declared, false
	}
	ids = make([]uint64, 0, count)
	base := pageHeaderSize + idx*8
	for i := uint64(0); i < count; i++ {
		o := base + int(i*8)
		ids = append(ids, binary.LittleEndian.Uint64(page[o:o+8]))
	}
	return ids, declared, true
}
