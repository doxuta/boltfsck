// Command boltfsck reports structural damage in a bbolt database file.
//
// It never opens the file with bbolt, so it works on files bbolt refuses to
// open and on files that make bbolt hang or fault. It does not repair
// anything.
//
// Usage:
//
//	boltfsck [-pagesize N] [-budget N] [-q] <file.db>
//
// Exit status is 0 when the walk completed and found nothing, 1 when problems
// were found or the walk could not complete, and 2 when the file could not be
// opened.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/doxuta/boltfsck"
)

func main() {
	pageSize := flag.Int("pagesize", 0, "page size override (default: read from the meta page)")
	budget := flag.Int("budget", 0, "maximum pages to read (default: 10x the high-water mark)")
	quiet := flag.Bool("q", false, "print only problems")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: boltfsck [flags] <file.db>\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	db, err := boltfsck.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "boltfsck: %v\n", err)
		os.Exit(2)
	}
	defer db.Close()

	rep := db.Check(boltfsck.Options{PageSize: *pageSize, Budget: *budget})
	if *quiet {
		for _, p := range rep.Problems {
			fmt.Println(p)
		}
	} else {
		fmt.Print(rep)
	}
	if !rep.OK() {
		os.Exit(1)
	}
}
