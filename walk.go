package boltfsck

import "encoding/binary"

// maxDepth bounds recursion so a hostile chain of pages cannot exhaust the
// goroutine stack. Real bbolt trees are a handful of levels deep.
const maxDepth = 1000

// maxSpanBytes bounds how much one page's overflow field is allowed to make us
// allocate. A 32-bit overflow count multiplied by the page size is otherwise an
// allocation bomb, and the corrupt files this tool exists for are exactly where
// such a value shows up.
const maxSpanBytes = 1 << 30

type walker struct {
	src      source
	rep      *Report
	ps       int64
	hwm      uint64
	budget   int
	used     int
	visited  map[uint64]uint64 // page id -> the page that claimed it
	onStack  map[uint64]bool
	freelist map[uint64]bool
	stopped  bool
}

func check(src source, opts Options) *Report {
	rep := &Report{MetaUsed: -1, PageSizeSource: -1, FileSize: src.Size()}

	ps := opts.PageSize
	if ps == 0 {
		ps, rep.PageSizeSource = discoverPageSize(src)
	}
	if ps == 0 {
		rep.PageSize = 0
		rep.add(NoValidMeta, 0, nil,
			"neither meta page validated and no plausible page size was found; this may not be a bbolt database")
		return rep
	}
	rep.PageSize = ps

	m0, h0, ok0 := readMetaAt(src, 0, ps)
	m1, h1, ok1 := readMetaAt(src, 1, ps)
	if ok0 {
		reportMeta(rep, 0, m0, h0)
	} else {
		rep.add(Truncated, 0, nil, "meta page 0 could not be read; file is %d bytes", src.Size())
	}
	if ok1 {
		reportMeta(rep, 1, m1, h1)
	} else {
		rep.add(Truncated, 1, nil, "meta page 1 could not be read; file is %d bytes", src.Size())
	}

	// bbolt picks the valid meta page with the higher transaction id, and
	// falls back to the other one when the newest write was torn. Doing the
	// same is what lets boltfsck read a file whose meta 0 is destroyed.
	use, m := -1, meta{}
	if ok0 && m0.valid() {
		use, m = 0, m0
	}
	if ok1 && m1.valid() && (use == -1 || m1.TxID > m.TxID) {
		use, m = 1, m1
	}
	if use == -1 {
		rep.add(NoValidMeta, 0, nil,
			"neither meta page is usable, so the tree cannot be entered; page-level problems above are all that can be determined")
		return rep
	}
	rep.MetaUsed = use
	rep.TxID = m.TxID
	rep.HighWater = m.HighWater

	// A page inside the high-water mark but past the end of the file is the
	// case that faults bbolt rather than erroring: the offset is validated
	// against the meta page, but the memory is not there.
	want := int64(m.HighWater) * int64(ps)
	if m.HighWater > 0 && src.Size() < want {
		rep.add(Truncated, uint64(src.Size()/int64(ps)), nil,
			"file is %d bytes but meta %d declares %d pages (%d bytes); pages from %d up are missing",
			src.Size(), use, m.HighWater, want, src.Size()/int64(ps))
	}

	budget := opts.Budget
	if budget <= 0 {
		budget = int(min64(uint64(10)*m.HighWater, 1<<20))
		if budget < 1024 {
			budget = 1024
		}
	}
	rep.Budget = budget

	w := &walker{
		src: src, rep: rep, ps: int64(ps), hwm: m.HighWater, budget: budget,
		visited: map[uint64]uint64{}, onStack: map[uint64]bool{}, freelist: map[uint64]bool{},
	}
	if m.freelistPersisted() {
		w.walkFreelist(m.Freelist)
	}
	w.visit(m.RootPgid, nil, 0)

	rep.PagesVisited = w.used
	rep.sort()
	return rep
}

func reportMeta(rep *Report, n int, m meta, h pageHeader) {
	if m.Magic != boltMagic {
		rep.add(BadMagic, uint64(n), nil, "meta %d magic is %#08x, want %#08x", n, m.Magic, boltMagic)
		return // version and checksum are meaningless without the magic
	}
	if m.Version != boltVersion {
		rep.add(BadVersion, uint64(n), nil, "meta %d version is %d, want %d", n, m.Version, boltVersion)
	}
	if m.Checksum != m.Computed {
		rep.add(BadChecksum, uint64(n), nil,
			"meta %d checksum is %#016x, computed %#016x", n, m.Checksum, m.Computed)
	}
	if h.Flags != metaPageFlag {
		rep.add(BadPageFlags, uint64(n), nil,
			"meta %d page flags are %#04x, want %#04x", n, h.Flags, metaPageFlag)
	}
}

// readSpan reads a page and any overflow pages that follow it. It returns the
// largest prefix it could actually read, so a truncated page is still
// inspectable rather than fatal.
func (w *walker) readSpan(pgid uint64, stack []uint64) ([]byte, pageHeader, bool) {
	off := int64(pgid) * w.ps
	if off < 0 || off+pageHeaderSize > w.src.Size() {
		w.rep.add(Truncated, pgid, stack,
			"page starts at byte %d but the file is only %d bytes", off, w.src.Size())
		return nil, pageHeader{}, false
	}
	hdr := make([]byte, pageHeaderSize)
	if _, err := w.src.ReadAt(hdr, off); err != nil {
		w.rep.add(Truncated, pgid, stack, "reading page header: %v", err)
		return nil, pageHeader{}, false
	}
	h, _ := decodePageHeader(hdr)

	span := (int64(h.Overflow) + 1) * w.ps
	if span <= 0 || span > maxSpanBytes {
		w.rep.add(CountOverflow, pgid, stack,
			"overflow field is %d, which spans %d bytes; refusing to allocate it", h.Overflow, span)
		span = w.ps
	}
	avail := w.src.Size() - off
	short := false
	if span > avail {
		short = true
		span = avail
	}
	buf := make([]byte, span)
	n, _ := w.src.ReadAt(buf, off)
	buf = buf[:n]
	if short || int64(n) < span {
		w.rep.add(Truncated, pgid, stack,
			"page declares %d overflow pages but only %d bytes are readable", h.Overflow, n)
	}
	return buf, h, len(buf) >= pageHeaderSize
}

func (w *walker) claim(pgid, owner uint64, stack []uint64) bool {
	if prev, seen := w.visited[pgid]; seen {
		if w.onStack[pgid] {
			w.rep.add(CycleRef, pgid, stack, "page is reachable from itself")
		} else {
			w.rep.add(SharedPage, pgid, stack, "page is also referenced from page %d", prev)
		}
		return false
	}
	w.visited[pgid] = owner
	return true
}

func (w *walker) visit(pgid uint64, stack []uint64, depth int) {
	if w.stopped {
		return
	}
	if depth > maxDepth {
		w.rep.add(CycleRef, pgid, stack, "reference chain exceeded %d levels; refusing to descend", maxDepth)
		return
	}
	if w.used >= w.budget {
		if !w.stopped {
			w.rep.add(BudgetExhausted, pgid, stack,
				"stopped after %d pages; the rest of the file was not examined", w.used)
			w.rep.Incomplete = true
			w.stopped = true
		}
		return
	}
	if pgid >= w.hwm {
		w.rep.add(OutOfBounds, pgid, stack,
			"page id is at or past the high-water mark of %d", w.hwm)
		return
	}
	if pgid < 2 {
		// Pages 0 and 1 are the meta pages. Nothing in the tree may point at
		// them, and following one would re-parse a meta page as a node.
		w.rep.add(MetaPageInTree, pgid, stack, "page %d is a meta page and cannot be part of the tree", pgid)
		return
	}
	if w.freelist[pgid] {
		w.rep.add(FreelistOverlap, pgid, stack, "page is on the freelist but is also reachable from the tree")
	}
	if !w.claim(pgid, parentOf(stack), stack) {
		return
	}
	w.used++

	buf, h, ok := w.readSpan(pgid, stack)
	if !ok {
		return
	}
	// Overflow pages belong to this page; claim them so a later reference to
	// one is reported as an overlap rather than silently accepted.
	for i := uint64(1); i <= uint64(h.Overflow) && i < uint64(maxDepth)*8; i++ {
		w.claim(pgid+i, pgid, stack)
	}
	if h.ID != pgid {
		w.rep.add(PageIDMismatch, pgid, stack, "page header says its id is %d", h.ID)
	}
	if !h.validFlags() {
		w.rep.add(BadPageFlags, pgid, stack, "page flags are %#04x (%s)", h.Flags, h.typ())
		return
	}

	next := append(append([]uint64{}, stack...), pgid)
	w.onStack[pgid] = true
	defer delete(w.onStack, pgid)

	switch h.Flags {
	case branchPageFlag:
		w.walkBranch(pgid, h, buf, next, depth)
	case leafPageFlag:
		w.walkLeaf(pgid, h, buf, next, depth)
	case metaPageFlag:
		w.rep.add(BadPageFlags, pgid, stack, "a meta page is referenced from inside the tree")
	case freelistPageFlag:
		w.rep.add(FreelistOverlap, pgid, stack, "a freelist page is referenced from inside the tree")
	}
}

func (w *walker) walkBranch(pgid uint64, h pageHeader, buf []byte, stack []uint64, depth int) {
	need := pageHeaderSize + int64(h.Count)*branchElemSize
	if need > int64(len(buf)) {
		w.rep.add(CountOverflow, pgid, stack,
			"branch page declares %d elements needing %d bytes, but the page holds %d", h.Count, need, len(buf))
		return
	}
	for i := 0; i < int(h.Count); i++ {
		e, ok := decodeBranchElem(buf, i)
		if !ok {
			w.rep.add(CountOverflow, pgid, stack, "branch element %d does not fit in the page", i)
			return
		}
		elemOff := pageHeaderSize + i*branchElemSize
		if s, end, ok := elemSpan(elemOff, e.Pos, e.Ksize, 0); !ok || end > len(buf) || s < 0 {
			w.rep.add(ElementOutOfBounds, pgid, stack,
				"branch element %d key spans bytes [%d,%d) of a %d-byte page", i, s, end, len(buf))
			continue
		}
		w.visit(e.Pgid, stack, depth+1)
		if w.stopped {
			return
		}
	}
}

func (w *walker) walkLeaf(pgid uint64, h pageHeader, buf []byte, stack []uint64, depth int) {
	need := pageHeaderSize + int64(h.Count)*leafElemSize
	if need > int64(len(buf)) {
		w.rep.add(CountOverflow, pgid, stack,
			"leaf page declares %d elements needing %d bytes, but the page holds %d", h.Count, need, len(buf))
		return
	}
	for i := 0; i < int(h.Count); i++ {
		e, ok := decodeLeafElem(buf, i)
		if !ok {
			w.rep.add(CountOverflow, pgid, stack, "leaf element %d does not fit in the page", i)
			return
		}
		elemOff := pageHeaderSize + i*leafElemSize
		s, end, spanOK := elemSpan(elemOff, e.Pos, e.Ksize, e.Vsize)
		if !spanOK || s < 0 || end > len(buf) {
			w.rep.add(ElementOutOfBounds, pgid, stack,
				"leaf element %d key+value spans bytes [%d,%d) of a %d-byte page", i, s, end, len(buf))
			continue
		}
		if !e.isBucket() {
			continue
		}
		// A bucket entry's value is an InBucket header. A non-zero root names
		// a page; a zero root means the whole sub-bucket is inlined into this
		// value, directly after the header. Treating an inline bucket as a
		// page reference walks one page instead of the whole database.
		vStart := s + int(e.Ksize)
		if end-vStart < inBucketSize {
			w.rep.add(ShortValue, pgid, stack,
				"leaf element %d is flagged as a bucket but its value is only %d bytes", i, end-vStart)
			continue
		}
		root := binary.LittleEndian.Uint64(buf[vStart : vStart+8])
		if root != 0 {
			w.visit(root, stack, depth+1)
			if w.stopped {
				return
			}
			continue
		}
		w.checkInline(pgid, buf[vStart+inBucketSize:end], i, stack)
	}
}

// checkInline validates a sub-bucket stored inside a leaf value. It consumes no
// page id, so it is checked in place rather than walked.
func (w *walker) checkInline(pgid uint64, inline []byte, elem int, stack []uint64) {
	if len(inline) < pageHeaderSize {
		w.rep.add(ShortValue, pgid, stack,
			"leaf element %d holds an inline bucket of only %d bytes", elem, len(inline))
		return
	}
	h, _ := decodePageHeader(inline)
	if h.Flags != leafPageFlag {
		w.rep.add(BadPageFlags, pgid, stack,
			"inline bucket in leaf element %d has flags %#04x, want leaf", elem, h.Flags)
		return
	}
	need := pageHeaderSize + int64(h.Count)*leafElemSize
	if need > int64(len(inline)) {
		w.rep.add(CountOverflow, pgid, stack,
			"inline bucket in leaf element %d declares %d elements needing %d bytes of %d",
			elem, h.Count, need, len(inline))
		return
	}
	for i := 0; i < int(h.Count); i++ {
		e, ok := decodeLeafElem(inline, i)
		if !ok {
			return
		}
		off := pageHeaderSize + i*leafElemSize
		s, end, spanOK := elemSpan(off, e.Pos, e.Ksize, e.Vsize)
		if !spanOK || s < 0 || end > len(inline) {
			w.rep.add(ElementOutOfBounds, pgid, stack,
				"inline bucket in leaf element %d: entry %d spans bytes [%d,%d) of %d", elem, i, s, end, len(inline))
		}
	}
}

func (w *walker) walkFreelist(pgid uint64) {
	if pgid >= w.hwm {
		w.rep.add(OutOfBounds, pgid, nil,
			"freelist page id is at or past the high-water mark of %d", w.hwm)
		return
	}
	if !w.claim(pgid, pgid, nil) {
		return
	}
	w.used++
	buf, h, ok := w.readSpan(pgid, nil)
	if !ok {
		return
	}
	for i := uint64(1); i <= uint64(h.Overflow) && i < uint64(maxDepth)*8; i++ {
		w.claim(pgid+i, pgid, nil)
	}
	if h.Flags != freelistPageFlag {
		w.rep.add(BadPageFlags, pgid, nil,
			"freelist page has flags %#04x (%s), want freelist", h.Flags, h.typ())
		return
	}
	ids, declared, ok := freelistIDs(buf, h)
	if !ok {
		w.rep.add(FreelistInvalid, pgid, nil,
			"freelist declares %d ids, which do not fit in its %d bytes", declared, len(buf))
		return
	}
	for _, id := range ids {
		if id >= w.hwm {
			w.rep.add(OutOfBounds, id, []uint64{pgid},
				"freelist entry is at or past the high-water mark of %d", w.hwm)
			continue
		}
		w.freelist[id] = true
	}
}

func parentOf(stack []uint64) uint64 {
	if len(stack) == 0 {
		return 0
	}
	return stack[len(stack)-1]
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
