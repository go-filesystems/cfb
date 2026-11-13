package cfb

import "strings"

// node describes a storage or a stream for the tests, which build their files
// with the package's Writer.
type node struct {
	Name     string
	Data     []byte
	Dir      bool
	Children []*node
	Created  uint64 // FILETIME
	Modified uint64 // FILETIME
}

// layout is what the tests that damage a file need to know about it.
type layout struct {
	DirOff    int64
	FatOff    int64
	DirSector uint32
	EntryIdx  map[string]int
}

func stream(name string, data []byte) *node { return &node{Name: name, Data: data} }
func storage(name string, kids ...*node) *node {
	return &node{Name: name, Dir: true, Children: kids}
}

// build writes the tree as a compound file of the given version.
func build(version int, root *node, gappy bool) ([]byte, layout) {
	opts := []WriterOption{WithVersion(version), WithLimits(1<<20, 1<<31)}
	if gappy {
		opts = append(opts, WithFreeSectorGaps())
	}
	w := NewWriter(opts...)
	w.SetRoot(Attrs{Created: filetime(root.Created), Modified: filetime(root.Modified)})
	var add func(prefix string, kids []*node)
	add = func(prefix string, kids []*node) {
		for _, k := range kids {
			path := strings.TrimPrefix(prefix+"/"+k.Name, "/")
			a := Attrs{Created: filetime(k.Created), Modified: filetime(k.Modified)}
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
	var b sliceWriter
	if _, err := w.WriteTo(&b); err != nil {
		panic(err)
	}
	l := w.Layout()
	return b, layout{DirOff: l.DirOffset, FatOff: l.FATOffset, DirSector: l.DirSector, EntryIdx: l.EntryIdx}
}

type sliceWriter []byte

func (s *sliceWriter) Write(p []byte) (int, error) { *s = append(*s, p...); return len(p), nil }
