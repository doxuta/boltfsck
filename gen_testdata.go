//go:build ignore

// Command gen_testdata writes the fixtures in testdata/.
//
// It is the only place bbolt is used to WRITE a database, and it is not part
// of the boltfsck package. Run it with:
//
//	go run gen_testdata.go
//
// The fixtures are checked in so that the README's demo needs no setup and so
// that the exact bytes that produced the measurements in the README can be
// re-examined.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	bbolt "go.etcd.io/bbolt"
)

const pageSize = 4096

func main() {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		log.Fatal(err)
	}
	healthy := "testdata/healthy.db"
	_ = os.Remove(healthy)

	db, err := bbolt.Open(healthy, 0o600, &bbolt.Options{PageSize: pageSize})
	if err != nil {
		log.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		users, err := tx.CreateBucket([]byte("users"))
		if err != nil {
			return err
		}
		for i := 0; i < 1200; i++ {
			k := []byte(fmt.Sprintf("user-%06d", i))
			v := []byte(fmt.Sprintf("value-%06d-padding-to-split-pages", i))
			if err := users.Put(k, v); err != nil {
				return err
			}
		}
		tiny, err := tx.CreateBucket([]byte("tiny"))
		if err != nil {
			return err
		}
		sub, err := tiny.CreateBucket([]byte("inlined"))
		if err != nil {
			return err
		}
		return sub.Put([]byte("k"), []byte("v"))
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Close(); err != nil {
		log.Fatal(err)
	}

	raw, err := os.ReadFile(healthy)
	if err != nil {
		log.Fatal(err)
	}
	hwm := binary.LittleEndian.Uint64(raw[16+40 : 16+48])
	fmt.Printf("healthy.db:   %d bytes, high-water mark %d pages\n", len(raw), hwm)

	// Truncate well inside the high-water mark. The tail of the tree is now
	// missing, which is what bbolt cannot survive: the page ids are still
	// declared valid by the meta page, but the bytes are not there.
	keep := 20 * pageSize
	if uint64(keep) >= hwm*pageSize {
		log.Fatalf("fixture too small to truncate: hwm %d pages", hwm)
	}
	if err := os.WriteFile("testdata/truncated.db", raw[:keep], 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("truncated.db: %d bytes (%d pages present, meta still declares %d)\n",
		keep, keep/pageSize, hwm)
}
