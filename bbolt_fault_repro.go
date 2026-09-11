//go:build ignore

// Command bbolt_fault_repro is the evidence behind the claim in README.md.
//
// It opens a database file with bbolt and runs bbolt's own Tx.Check, in a
// child process, N times, and reports how many of those processes died on a
// fault rather than returning an error.
//
//	go run bbolt_fault_repro.go testdata/truncated.db 100
//
// The child does the work; the parent only counts outcomes, because the
// failure being measured kills the process and cannot be recovered from
// in-process. That is the entire point: a SIGSEGV or SIGBUS raised by touching
// a page past the end of the mapping is a runtime throw, not a panic, so no
// amount of defer/recover in a caller can turn it into an error value.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

func main() {
	if os.Getenv("BBOLT_REPRO_CHILD") != "" {
		child(os.Args[1])
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run bbolt_fault_repro.go <file.db> [trials]")
		os.Exit(2)
	}
	path := os.Args[1]
	trials := 100
	if len(os.Args) > 2 {
		n, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad trial count: %v\n", err)
			os.Exit(2)
		}
		trials = n
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var faults, completed, other int
	var lastFault string
	for i := 0; i < trials; i++ {
		cmd := exec.Command(self, path)
		cmd.Env = append(os.Environ(), "BBOLT_REPRO_CHILD=1")
		out, err := cmd.CombinedOutput()
		s := string(out)
		switch {
		case strings.Contains(s, "SIGSEGV") || strings.Contains(s, "SIGBUS") || strings.Contains(s, "fatal error"):
			faults++
			lastFault = firstLines(s, 4)
		case strings.Contains(s, "RESULT=COMPLETED"):
			completed++
		default:
			other++
			if err != nil && lastFault == "" {
				lastFault = firstLines(s, 4)
			}
		}
	}
	fmt.Printf("file:      %s\n", path)
	fmt.Printf("trials:    %d separate processes\n", trials)
	fmt.Printf("faulted:   %d   (process killed; not an error a caller can handle)\n", faults)
	fmt.Printf("completed: %d\n", completed)
	fmt.Printf("other:     %d\n", other)
	if lastFault != "" {
		fmt.Printf("\nlast fault:\n%s\n", lastFault)
	}
}

func child(path string) {
	go func() {
		time.Sleep(30 * time.Second)
		fmt.Println("RESULT=HUNG")
		os.Exit(3)
	}()
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		fmt.Printf("RESULT=OPEN_ERROR %v\n", err)
		return
	}
	defer db.Close()
	n := 0
	_ = db.View(func(tx *bbolt.Tx) error {
		for range tx.Check() {
			if n++; n > 50 {
				break
			}
		}
		return nil
	})
	fmt.Printf("RESULT=COMPLETED errs=%d\n", n)
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
