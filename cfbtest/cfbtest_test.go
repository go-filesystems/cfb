package cfbtest

import (
	"bytes"
	"testing"

	"github.com/go-filesystems/cfb"
)

func TestBuildDelegatesToTheWriter(t *testing.T) {
	root := Storage("Root Entry", Stream("a", []byte("hello")), Storage("d", Stream("b", bytes.Repeat([]byte{1}, 5000))))
	root.Created = 132_000_000_000_000_000
	root.Children[0].Created = 0
	for _, v := range []int{3, 4} {
		data, lay := Build(v, root, v == 4)
		f, err := cfb.Open(bytes.NewReader(data), int64(len(data)))
		if err != nil || f.Version() != v {
			t.Fatalf("v%d: %v", v, err)
		}
		if got, _ := f.ReadAll(f.Lookup("d/b"), 1<<20); len(got) != 5000 {
			t.Fatalf("v%d: %d bytes", v, len(got))
		}
		if f.Root().Created.IsZero() || lay.DirOff == 0 || lay.FatOff == 0 || lay.EntryIdx["b"] == 0 {
			t.Fatalf("v%d: %+v %+v", v, f.Root(), lay)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a bad tree must panic")
		}
	}()
	Build(3, Storage("Root Entry", Stream("bad/name", nil)), false)
}
