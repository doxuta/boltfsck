package boltfsck

import (
	"fmt"
	"sort"
	"strings"
)

// ProblemCode identifies a class of defect. The codes are part of the API:
// they exist so a caller can branch on the kind of damage instead of matching
// on message text.
type ProblemCode string

const (
	// NoValidMeta means neither meta page passed magic, version and checksum,
	// so the tree could not be entered at all.
	NoValidMeta ProblemCode = "no_valid_meta"
	// BadMagic means a meta page does not carry bbolt's magic number.
	BadMagic ProblemCode = "bad_magic"
	// BadVersion means a meta page declares an unsupported format version.
	BadVersion ProblemCode = "bad_version"
	// BadChecksum means a meta page's stored checksum does not match its
	// contents.
	BadChecksum ProblemCode = "bad_checksum"
	// Truncated means a page inside the declared high-water mark lies beyond
	// the end of the file. This is the case bbolt cannot survive: the page is
	// inside the mapping's logical range but outside the mapping itself.
	Truncated ProblemCode = "truncated"
	// OutOfBounds means a page id points at or past the high-water mark.
	OutOfBounds ProblemCode = "out_of_bounds"
	// CycleRef means a page is reachable from itself; the reference stack that
	// closes the loop is reported with it.
	CycleRef ProblemCode = "cycle_ref"
	// SharedPage means a page is referenced from two places in the tree, which
	// a B+tree never does.
	SharedPage ProblemCode = "shared_page"
	// BadPageFlags means a page header's type flags are not exactly one of
	// branch, leaf, meta or freelist.
	BadPageFlags ProblemCode = "bad_page_flags"
	// MetaPageInTree means a branch or leaf entry points at page 0 or 1, which
	// are the meta pages and are never part of the tree.
	MetaPageInTree ProblemCode = "meta_page_in_tree"
	// CountOverflow means a page declares more elements than its own bytes can
	// hold.
	CountOverflow ProblemCode = "count_overflow"
	// ElementOutOfBounds means a key or value extends past the end of its page.
	ElementOutOfBounds ProblemCode = "element_out_of_bounds"
	// PageIDMismatch means a page header's self-reported id differs from the id
	// it was reached by.
	PageIDMismatch ProblemCode = "page_id_mismatch"
	// BudgetExhausted means the walk stopped early because it hit its work
	// budget. The report is then incomplete, and says so.
	BudgetExhausted ProblemCode = "budget_exhausted"
	// FreelistInvalid means the freelist page could not be decoded.
	FreelistInvalid ProblemCode = "freelist_invalid"
	// FreelistOverlap means a page is on the freelist and also reachable from
	// the tree.
	FreelistOverlap ProblemCode = "freelist_overlap"
	// ShortValue means a bucket entry's value is too small to hold a bucket
	// header.
	ShortValue ProblemCode = "short_value"
)

// maxProblems bounds how many problems one report will hold. A sufficiently
// damaged file can name a defect on every page, and a report that exhausts
// memory is just another way of crashing.
const maxProblems = 10000

// Problem is a single defect found in a database file.
type Problem struct {
	Code ProblemCode
	// Pgid is the page the problem was found on or refers to.
	Pgid uint64
	// Stack is the chain of page ids walked to reach Pgid, outermost first.
	// It is set for problems found during the tree walk.
	Stack []uint64
	Msg   string
}

func (p Problem) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: page %d: %s", p.Code, p.Pgid, p.Msg)
	if len(p.Stack) > 0 {
		parts := make([]string, len(p.Stack))
		for i, id := range p.Stack {
			parts[i] = fmt.Sprint(id)
		}
		fmt.Fprintf(&b, " (via %s)", strings.Join(parts, "->"))
	}
	return b.String()
}

// Report is the result of checking one database file.
type Report struct {
	Problems []Problem

	// PageSize is the page size the file was read with.
	PageSize int
	// PageSizeSource records where PageSize came from: 0 or 1 for the meta
	// page it was read from, and -1 when it was guessed because no meta page
	// validated.
	PageSizeSource int
	// MetaUsed is the meta page the walk was rooted at, or -1 if neither meta
	// page was usable.
	MetaUsed int
	// HighWater is the page count the chosen meta page declares.
	HighWater uint64
	// TxID is the transaction id of the chosen meta page.
	TxID uint64
	// FileSize is the size of the file in bytes.
	FileSize int64
	// PagesVisited counts pages the walk actually read.
	PagesVisited int
	// Budget is the work budget the walk ran under.
	Budget int
	// Incomplete is true when the walk stopped early, so an absence of
	// problems below it proves nothing.
	Incomplete bool
}

// OK reports whether the file is free of detected problems and the walk ran to
// completion. A false OK on an incomplete walk is deliberate: a partial check
// must never read as a clean bill of health.
func (r *Report) OK() bool { return len(r.Problems) == 0 && !r.Incomplete }

// Count returns how many problems carry the given code.
func (r *Report) Count(c ProblemCode) int {
	n := 0
	for _, p := range r.Problems {
		if p.Code == c {
			n++
		}
	}
	return n
}

func (r *Report) add(c ProblemCode, pgid uint64, stack []uint64, format string, args ...any) {
	if len(r.Problems) >= maxProblems {
		if !r.Incomplete {
			r.Incomplete = true
			r.Problems = append(r.Problems, Problem{
				Code: BudgetExhausted,
				Msg:  fmt.Sprintf("stopped recording after %d problems; the file is damaged beyond itemising", maxProblems),
			})
		}
		return
	}
	var s []uint64
	if len(stack) > 0 {
		s = append(s, stack...)
	}
	r.Problems = append(r.Problems, Problem{
		Code: c, Pgid: pgid, Stack: s, Msg: fmt.Sprintf(format, args...),
	})
}

func (r *Report) sort() {
	sort.SliceStable(r.Problems, func(i, j int) bool {
		if r.Problems[i].Pgid != r.Problems[j].Pgid {
			return r.Problems[i].Pgid < r.Problems[j].Pgid
		}
		return r.Problems[i].Code < r.Problems[j].Code
	})
}

// String renders a human-readable summary.
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "page size:     %d", r.PageSize)
	switch r.PageSizeSource {
	case -1:
		b.WriteString(" (guessed; no meta page validated)\n")
	default:
		fmt.Fprintf(&b, " (from meta %d)\n", r.PageSizeSource)
	}
	fmt.Fprintf(&b, "file size:     %d bytes\n", r.FileSize)
	if r.MetaUsed >= 0 {
		fmt.Fprintf(&b, "meta used:     %d (txid %d)\n", r.MetaUsed, r.TxID)
		fmt.Fprintf(&b, "high water:    %d pages\n", r.HighWater)
	} else {
		b.WriteString("meta used:     none\n")
	}
	fmt.Fprintf(&b, "pages visited: %d (budget %d)\n", r.PagesVisited, r.Budget)
	if r.Incomplete {
		b.WriteString("WALK INCOMPLETE - absence of problems below proves nothing\n")
	}
	if len(r.Problems) == 0 {
		b.WriteString("problems:      none\n")
		return b.String()
	}
	fmt.Fprintf(&b, "problems:      %d\n", len(r.Problems))
	for _, p := range r.Problems {
		fmt.Fprintf(&b, "  %s\n", p.String())
	}
	return b.String()
}
