package boltfsck_test

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"testing"

	"github.com/doxuta/boltfsck"
)

// setMetaField rewrites one uint64 field at meta offset off in both meta pages
// and re-seals their checksums, so an absurd value is still accepted as valid.
func setMetaField(b []byte, ps, off int, v uint64) {
	for i := 0; i < 2; i++ {
		m := b[i*ps+16 : i*ps+16+64]
		binary.LittleEndian.PutUint64(m[off:off+8], v)
		h := fnv.New64a()
		_, _ = h.Write(m[:56])
		binary.LittleEndian.PutUint64(m[56:64], h.Sum64())
	}
}

// healthyImage is a four-page image with one ordinary key; the baseline every
// case below perturbs.
func healthyImage(hwm uint64, root uint64) []byte {
	s := newSynth(4096, 8, 4)
	p := s.page(4, 0x02, 1)
	putLeafElem(p, 0, 0, []byte("k"), []byte("v"), 16+16)
	b := s.build()
	setMetaField(b, 4096, 40, hwm)
	setMetaField(b, 4096, 16, root)
	return b
}

// TestRegress20261011 pins integer-overflow holes found by hand-crafting
// headers: each case either panicked or produced a confidently wrong report.
func TestRegress20261011(t *testing.T) {
	tests := []struct {
		name       string
		image      func() []byte
		opts       boltfsck.Options
		want       boltfsck.ProblemCode // must be reported ("" = none required)
		forbid     boltfsck.ProblemCode // must not be reported ("" = no constraint)
		wantOK     bool
		wantSource int // expected PageSizeSource when non-zero
	}{
		{
			// (1+count)*8 wraps to 0 and the fit check passes, then
			// make([]uint64, 0, count) panics: makeslice: cap out of range.
			name: "freelist overflow-count form with a count that wraps the byte arithmetic",
			image: func() []byte {
				s := newSynth(4096, 5, 2)
				s.freelist = 3
				s.page(2, 0x02, 0)
				fl := s.page(3, 0x10, 0xFFFF)
				binary.LittleEndian.PutUint64(fl[16:24], 1<<61-1)
				return s.build()
			},
			want: boltfsck.FreelistInvalid,
		},
		{
			// HighWater*pageSize overflows int64 to 0, so a 32 KiB file that
			// declares 2^62 pages is reported clean.
			name:  "high-water mark times page size overflows int64",
			image: func() []byte { return healthyImage(1<<62, 4) },
			want:  boltfsck.Truncated,
		},
		{
			// pgid*pageSize wraps to 16384, so page 2^52+4 is read as page 4
			// and the only finding is a page_id_mismatch on a page that does
			// not exist.
			name:   "page id times page size wraps to a lower page",
			image:  func() []byte { return healthyImage(1<<62, 1<<52+4) },
			want:   boltfsck.Truncated,
			forbid: boltfsck.PageIDMismatch,
		},
		{
			// A huge override has the same aliasing effect: 4*2^62 wraps to
			// offset 0 and meta page 0 is parsed as the root.
			name:   "huge page size override wraps page offsets",
			image:  func() []byte { return healthyImage(8, 4) },
			opts:   boltfsck.Options{PageSize: 1 << 62},
			want:   boltfsck.Truncated,
			forbid: boltfsck.PageIDMismatch,
		},
		{
			// An explicit override was rendered as "guessed; no meta page
			// validated", which is not where the value came from.
			name:       "page size override is attributed to the caller",
			image:      func() []byte { return healthyImage(8, 4) },
			opts:       boltfsck.Options{PageSize: 4096},
			wantSource: -2,
			wantOK:     true,
		},
		{
			// span = (overflow+1)*MinInt64 is negative, is replaced by the
			// (negative) page size and handed to make: makeslice: len out of range.
			name:   "most negative page size override",
			image:  func() []byte { return healthyImage(8, 4) },
			opts:   boltfsck.Options{PageSize: math.MinInt64},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := boltfsck.CheckBytes(tt.image(), tt.opts)
			if rep == nil {
				t.Fatal("nil report")
			}
			if tt.want != "" && rep.Count(tt.want) == 0 {
				t.Errorf("want a %s problem, got:\n%s", tt.want, rep)
			}
			if tt.forbid != "" && rep.Count(tt.forbid) != 0 {
				t.Errorf("got a %s problem from an aliased page offset:\n%s", tt.forbid, rep)
			}
			if tt.wantSource != 0 && rep.PageSizeSource != tt.wantSource {
				t.Errorf("PageSizeSource = %d, want %d:\n%s", rep.PageSizeSource, tt.wantSource, rep)
			}
			if rep.OK() != tt.wantOK {
				t.Errorf("OK() = %v, want %v:\n%s", rep.OK(), tt.wantOK, rep)
			}
		})
	}
}
