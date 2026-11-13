// Package cfbtest builds compound files from a tree of nodes, for tests of
// code that reads them. It is a thin layer over cfb.Writer, public and
// versioned with the module, and not a general MS-CFB writer: use cfb.Writer
// for that. It is not hardened for untrusted input: a bad tree panics.
package cfbtest

import (
	"bytes"
	"strings"
	"time"

	"github.com/go-filesystems/cfb"
)

// Node describes a storage or a stream.
type Node struct {
	Name     string
	Data     []byte
	Dir      bool
	Children []*Node
	Created  uint64 // FILETIME
	Modified uint64 // FILETIME
}

// Stream returns a stream node.
func Stream(name string, data []byte) *Node { return &Node{Name: name, Data: data} }

// Storage returns a storage node; the root is a Storage too.
func Storage(name string, kids ...*Node) *Node {
	return &Node{Name: name, Dir: true, Children: kids}
}

// Layout tells where the writer put things, for tests that corrupt a file.
type Layout struct {
	DirOff    int64 // byte offset of the directory
	FatOff    int64 // byte offset of the first FAT sector
	DirSector uint32
	EntryIdx  map[string]int // name -> directory entry index
}

func filetime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v/10_000_000)-11644473600, int64(v%10_000_000)*100).UTC()
}

// Build returns a compound file of the given major version (3 or 4). With
// gappy, a free sector follows each data sector so chains are not contiguous.
func Build(version int, root *Node, gappy bool) ([]byte, Layout) {
	opts := []cfb.WriterOption{cfb.WithVersion(version), cfb.WithLimits(1<<20, 1<<31)}
	if gappy {
		opts = append(opts, cfb.WithFreeSectorGaps())
	}
	w := cfb.NewWriter(opts...)
	w.SetRoot(cfb.Attrs{Created: filetime(root.Created), Modified: filetime(root.Modified)})
	var add func(prefix string, kids []*Node)
	add = func(prefix string, kids []*Node) {
		for _, k := range kids {
			path := strings.TrimPrefix(prefix+"/"+k.Name, "/")
			a := cfb.Attrs{Created: filetime(k.Created), Modified: filetime(k.Modified)}
			var err error
			if k.Dir {
				err = w.AddStorage(path, a)
			} else {
				err = w.AddStream(path, k.Data, a)
			}
			if err != nil {
				panic(err)
			}
			add(path, k.Children)
		}
	}
	add("", root.Children)
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		panic(err)
	}
	l := w.Layout()
	return b.Bytes(), Layout{DirOff: l.DirOffset, FatOff: l.FATOffset, DirSector: l.DirSector, EntryIdx: l.EntryIdx}
}
