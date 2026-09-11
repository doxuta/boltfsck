# boltfsck

Inspect a corrupt [bbolt](https://github.com/etcd-io/bbolt) database file without opening it with bbolt.

```
go install github.com/doxuta/boltfsck/cmd/boltfsck@latest
```

## Why it exists

When a bbolt file goes bad, the tools you reach for are built on the component that
went bad. `bbolt check` calls `Tx.Check`, which reaches pages through the same
mmap-and-`unsafe.Pointer` loader the damage defeats. Every third-party bbolt browser
imports `go.etcd.io/bbolt` and inherits that loader. So the first thing you do to a
damaged file is hand it to the code least able to cope with it.

That is a structural problem, not a bug to be waited out. A page id inside the
high-water mark the meta page declares, but past the end of the file, produces an
address that is computed before anything checks whether it is mapped. Touching it
raises SIGSEGV or SIGBUS, which the Go runtime turns into a fatal throw. `recover`
cannot catch it. There is no error value to return.

`boltfsck` reads the file with `ReadAt` into ordinary heap buffers and decodes every
field with `encoding/binary`. It never maps the file and never uses `unsafe`. Bounds
are checked before each read, the walk carries a visited set so cyclic references
terminate, and the whole thing runs under a work budget. It always returns a report.

## Try it

The repository ships two fixtures: a healthy database, and the same database
truncated inside its own declared high-water mark.

```
git clone https://github.com/doxuta/boltfsck && cd boltfsck
go run ./cmd/boltfsck testdata/truncated.db
```

```
page size:     4096 (from meta 0)
file size:     81920 bytes
meta used:     0 (txid 2)
high water:    45 pages
pages visited: 2 (budget 1024)
problems:      3
  truncated: page 20: file is 81920 bytes but meta 0 declares 45 pages (184320 bytes); pages from 20 up are missing
  truncated: page 43: page starts at byte 176128 but the file is only 81920 bytes
  truncated: page 44: page starts at byte 180224 but the file is only 81920 bytes
```

Exit status is 0 when the walk completed and found nothing, 1 when it found problems
or could not complete, 2 when the file could not be opened.

## The measurement

`testdata/truncated.db` is the same file in both columns.

| | bbolt v1.5.0 `Tx.Check` | boltfsck |
|---|---|---|
| 100 separate processes | **99 killed by a fault**, 1 completed | 100 identical reports |
| failure mode | SIGSEGV or SIGBUS, varying per run | 3 named problems, exit 1 |
| where | inside `common.(*Page).IsFreelistPage`, called from `freelist.(*shared).Read` | n/a |

Reproduce it yourself — the program is in this repository and it is what produced the
numbers above:

```
go run bbolt_fault_repro.go testdata/truncated.db 100
go run bbolt_fault_repro.go testdata/healthy.db 10    # control: 0 faults
```

Two details worth stating plainly, because they cut against a tidier story:

- **The crash is not even reliable.** One process in a hundred completed and reported a
  single error. You cannot conclude a file is fine because `bbolt check` returned.
- **Whether a given truncated file kills bbolt depends on that file's layout**, not on
  luck at runtime. Truncating thirty separately-built databases the same way, only five
  faulted; truncating *one* database and opening it a hundred times faulted every time
  but one. So "it worked on my file" generalises to nothing.

`boltfsck`'s output on that file is byte-identical across 200 runs, which one of the
tests asserts.

## What it reports

Each problem carries a code, so callers can branch on the kind of damage instead of
matching on message text.

| code | meaning |
|---|---|
| `no_valid_meta` | neither meta page passed magic, version and checksum |
| `bad_magic`, `bad_version`, `bad_checksum` | a specific meta page is unusable |
| `truncated` | a page inside the high-water mark lies past the end of the file |
| `out_of_bounds` | a page id is at or past the high-water mark |
| `cycle_ref` | a page is reachable from itself, with the reference stack that closes the loop |
| `shared_page` | a page is referenced from two places, which a B+tree never does |
| `meta_page_in_tree` | a branch or leaf entry points at page 0 or 1 |
| `bad_page_flags` | a page's type flags are not exactly one of branch, leaf, meta, freelist |
| `count_overflow` | a page declares more elements than its own bytes can hold |
| `element_out_of_bounds` | a key or value extends past the end of its page |
| `page_id_mismatch` | a page header's self-reported id differs from the id it was reached by |
| `freelist_invalid`, `freelist_overlap` | the freelist cannot be decoded, or it claims a page the tree still uses |
| `short_value` | a bucket entry's value is too small to hold a bucket header |
| `budget_exhausted` | the walk stopped early, so the report is incomplete |

As a library:

```go
db, err := boltfsck.Open("some.db")
if err != nil { return err }
defer db.Close()

rep := db.Check(boltfsck.Options{})
if !rep.OK() {
    for _, p := range rep.Problems {
        log.Println(p.Code, p.Pgid, p.Msg)
    }
}
```

`boltfsck.CheckBytes` does the same for an image you already hold in memory.

## Limitations

Written here rather than left for you to find.

- **It diagnoses; it does not repair.** There is no `-fix`, no salvage, no recovery of
  the keys in a damaged page. Repair is a different tool with a different risk profile,
  and bbolt already ships `surgery` commands for parts of it.
- **A flipped byte inside a key or value is undetectable, by design.** bbolt checksums
  only the meta page. Nothing in the format lets any tool, this one included, tell a
  corrupted value from a value you meant to store.
- **It does not check key ordering within a page**, nor that the tree is balanced.
  `Tx.Check` does check ordering, on files it survives.
- **It does not report unreachable pages.** Deciding that a page below the high-water
  mark is genuinely leaked requires assumptions about freelist state that are not safe
  to make from the outside, and a checker that cries wolf on healthy files is worse
  than no checker.
- **Page-size discovery can fail.** If both meta pages are destroyed, the page size is
  guessed from a small candidate list; a database written with an unusual page size and
  two dead meta pages will not be walked. The report says when the size was guessed.
- **The on-disk format is mirrored by hand**, not imported. That is the whole point, and
  it is also the maintenance cost: a future bbolt format change needs a matching change
  here. The constants are in `page.go` and the differential test against bbolt is what
  would catch the drift.

## Verified

```
go test ./...                    all pass
go test -race ./...              clean
go vet ./...                     clean
statement coverage (library)     88.3%
go test -fuzz=FuzzCheckBytes     30s from a cold cache: 1.74M execs, 0 failures
mutation check                   8 hand-written defects, 8 caught by the suite
```

The suite includes a differential test: a database bbolt itself pronounces healthy must
produce an empty report. Without it, a checker that flagged everything would pass every
corruption test.

`bbolt` is a **test-only** dependency, used to write fixtures and as that oracle. The
library imports nothing outside the standard library, and a test asserts it — if
`boltfsck` ever imports bbolt it inherits the loader it exists to avoid.

## Prior art and credit

- [etcd-io/bbolt](https://github.com/etcd-io/bbolt) by the etcd authors, originally
  [boltdb/bolt](https://github.com/boltdb/bolt) by Ben Johnson. The on-disk format is
  theirs; this tool only reads it. bbolt's `internal/common` package is where the layout
  mirrored in `page.go` and `meta.go` comes from.
- The problem is a live one upstream. [bbolt#581](https://github.com/etcd-io/bbolt/issues/581)
  "Ensure the check command do not panic" was filed by maintainer `ahrtr` on 2023-10-18 and
  carries `priority/important` and `stage/tracked`; it is still open.
  [bbolt#877](https://github.com/etcd-io/bbolt/issues/877) "Check of corrupted file deadlocks"
  was filed by `serathius` on 2024-12-20 and is labelled `area/corruption`.
  [bbolt#1257](https://github.com/etcd-io/bbolt/issues/1257) "`Tx.Check` can hang or
  dereference invalid pages when branch references are corrupt" was filed on 2026-08-14.
  Upstream work on all three is ongoing and welcome; none of it removes the structural
  reason for a reader that does not share bbolt's loader.
- `bbolt check`, `bbolt page`, and `bbolt surgery` remain the right tools for a file
  bbolt can open.

Built with an AI-agent workflow: the code, tests and this README were written by an agent
run by [@doxuta](https://github.com/doxuta), who reviewed and published them. The bbolt
fault numbers above were produced by running `bbolt_fault_repro.go`, not estimated.

## License

MIT. See [LICENSE](LICENSE).
