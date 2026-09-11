package boltfsck

import (
	"encoding/binary"
	"hash/fnv"
)

// meta is the decoded contents of a bbolt meta page.
type meta struct {
	Magic     uint32
	Version   uint32
	PageSize  uint32
	Flags     uint32
	RootPgid  uint64
	RootSeq   uint64
	Freelist  uint64
	HighWater uint64
	TxID      uint64
	Checksum  uint64

	// Computed is the checksum boltfsck calculates over the same bytes bbolt
	// hashes. It is kept so a mismatch can be reported with both values.
	Computed uint64
}

// decodeMeta reads the meta structure that follows a page header.
func decodeMeta(page []byte) (meta, bool) {
	if len(page) < pageHeaderSize+metaSize {
		return meta{}, false
	}
	b := page[pageHeaderSize : pageHeaderSize+metaSize]
	m := meta{
		Magic:     binary.LittleEndian.Uint32(b[0:4]),
		Version:   binary.LittleEndian.Uint32(b[4:8]),
		PageSize:  binary.LittleEndian.Uint32(b[8:12]),
		Flags:     binary.LittleEndian.Uint32(b[12:16]),
		RootPgid:  binary.LittleEndian.Uint64(b[16:24]),
		RootSeq:   binary.LittleEndian.Uint64(b[24:32]),
		Freelist:  binary.LittleEndian.Uint64(b[32:40]),
		HighWater: binary.LittleEndian.Uint64(b[40:48]),
		TxID:      binary.LittleEndian.Uint64(b[48:56]),
		Checksum:  binary.LittleEndian.Uint64(b[56:64]),
	}
	h := fnv.New64a()
	_, _ = h.Write(b[:metaSumOffset])
	m.Computed = h.Sum64()
	return m, true
}

func (m meta) valid() bool {
	return m.Magic == boltMagic && m.Version == boltVersion && m.Checksum == m.Computed
}

func (m meta) freelistPersisted() bool { return m.Freelist != pgidNoFreelist }

// readMetaAt reads meta page n (0 or 1) assuming the given page size.
func readMetaAt(src source, n int, pageSize int) (meta, pageHeader, bool) {
	buf := make([]byte, pageHeaderSize+metaSize)
	off := int64(n) * int64(pageSize)
	if _, err := src.ReadAt(buf, off); err != nil {
		return meta{}, pageHeader{}, false
	}
	h, ok := decodePageHeader(buf)
	if !ok {
		return meta{}, pageHeader{}, false
	}
	m, ok := decodeMeta(buf)
	if !ok {
		return meta{}, h, false
	}
	return m, h, true
}

// discoverPageSize determines the page size to read the file with.
//
// Meta page 0 always starts at offset 0, so its pageSize field can be read
// without knowing the page size first. When meta 0 is damaged that field
// cannot be trusted, and meta 1 lives at an offset that depends on the very
// value we are missing — so each plausible page size is tried and the one that
// yields a checksum-valid meta 1 wins. A file whose page size is genuinely
// unrecoverable returns 0.
func discoverPageSize(src source) (size int, fromMeta int) {
	// Meta 0, read at a fixed offset.
	if m, _, ok := readMetaAt(src, 0, 0); ok && m.valid() && plausiblePageSize(m.PageSize) {
		return int(m.PageSize), 0
	}
	// Meta 1, whose location depends on the page size. Try each candidate.
	for _, ps := range candidatePageSizes {
		if m, _, ok := readMetaAt(src, 1, ps); ok && m.valid() && int(m.PageSize) == ps {
			return ps, 1
		}
	}
	// Last resort: an unvalidated page-size field from meta 0. A file with a
	// corrupt checksum but an intact page-size field is still worth walking.
	if m, _, ok := readMetaAt(src, 0, 0); ok && plausiblePageSize(m.PageSize) {
		return int(m.PageSize), -1
	}
	return 0, -1
}

func plausiblePageSize(v uint32) bool {
	if v < 512 || v > 1<<20 {
		return false
	}
	return v&(v-1) == 0 // power of two
}
