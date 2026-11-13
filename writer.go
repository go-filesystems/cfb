package cfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Sector numbers with a meaning of their own (MS-CFB, FAT sectors).
const (
	fatSect uint32 = 0xFFFFFFFD
	difSect uint32 = 0xFFFFFFFC
)

// ErrArgument reports something a Writer refuses to write: a name MS-CFB does
// not allow, a name used twice, a missing parent, or a size above a limit.
var ErrArgument = errors.New("cfb: invalid argument")

// Attrs are the optional attributes of a storage or a stream. Times that are
// the zero time.Time (or before 1601) are written as "not recorded".
type Attrs struct {
	CLSID     [16]byte
	StateBits uint32
	Created   time.Time
	Modified  time.Time
}

// Layout tells where a Writer put the structures, for tests that damage a file
// on purpose.
type Layout struct {
	DirOffset int64          // byte offset of the first directory sector
	FATOffset int64          // byte offset of the first FAT sector
	DirSector uint32         // number of the first directory sector
	EntryIdx  map[string]int // leaf name to directory entry number
}

type wnode struct {
	name     string
	dir      bool
	data     []byte
	attrs    Attrs
	children []*wnode
}

// Writer builds a compound file in memory and writes it out. It writes
// version 3 (512-byte sectors) by default, or version 4 (4096-byte sectors)
// with WithVersion(4); a FAT, a DIFAT when the FAT needs more than 109
// sectors, a mini FAT and mini stream for streams under 4096 bytes, and the
// directory, with balanced sibling trees whose nodes are all black. MS-CFB
// 2.6.4 states the invariants (root black, no two consecutive red nodes, left
// sorts before right) and that "the simplest implementation of the preceding
// invariants would be to mark every node as black, in which case the tree is
// simply a binary tree"; it has no black-height rule. What it writes is read
// back by Open.
//
// A Writer refuses what MS-CFB does not allow and what would be unreasonable
// to hold (see WithLimits); it is not safe for concurrent use.
type Writer struct {
	version    int
	gaps       bool
	maxEntries int
	maxBytes   int64
	root       *wnode
	entries    int
	bytes      int64
	layout     Layout
}

// WriterOption configures NewWriter.
type WriterOption func(*Writer)

// WithVersion selects the major version: 3 (512-byte sectors, the default) or
// 4 (4096-byte sectors).
func WithVersion(v int) WriterOption { return func(w *Writer) { w.version = v } }

// WithFreeSectorGaps leaves a free sector after every data sector, so that no
// chain is contiguous. It exists to test readers.
func WithFreeSectorGaps() WriterOption { return func(w *Writer) { w.gaps = true } }

// WithLimits sets the most directory entries and the most stream bytes in all
// that a Writer accepts. The defaults are 1<<20 entries and 1<<31 bytes (2 GiB,
// the most a version 3 file can hold in one stream, and the cap for version 3
// whatever is asked).
func WithLimits(maxEntries int, maxBytes int64) WriterOption {
	return func(w *Writer) { w.maxEntries, w.maxBytes = maxEntries, maxBytes }
}

// NewWriter returns a Writer holding only the root storage.
func NewWriter(opts ...WriterOption) *Writer {
	w := &Writer{version: 3, maxEntries: 1 << 20, maxBytes: 1 << 31, root: &wnode{name: "Root Entry", dir: true}}
	for _, o := range opts {
		o(w)
	}
	if w.version == 3 { // a version 3 stream or mini stream is at most 2 GiB
		w.maxBytes = min(w.maxBytes, 1<<31)
	}
	return w
}

// SetRoot sets the attributes of the root storage (its class ID and times).
func (w *Writer) SetRoot(a Attrs) { w.root.attrs = a }

// AddStorage adds a storage at the slash-separated path; its parent must exist.
func (w *Writer) AddStorage(path string, a Attrs) error {
	_, err := w.add(path, true, nil, a)
	return err
}

// AddStream adds a stream with the given content, which the Writer keeps a
// reference to: do not change it before WriteTo.
func (w *Writer) AddStream(path string, data []byte, a Attrs) error {
	_, err := w.add(path, false, data, a)
	return err
}

func validName(name string) error {
	u := utf16.Encode([]rune(name))
	switch {
	case name == "":
		return fmt.Errorf("%w: empty name", ErrArgument)
	case len(u) > 31: // 32 units with the terminating NUL
		return fmt.Errorf("%w: name %q is %d UTF-16 units, at most 31", ErrArgument, name, len(u))
	case strings.ContainsAny(name, "/\\:!\x00"):
		return fmt.Errorf("%w: name %q contains one of / \\ : ! or NUL", ErrArgument, name)
	}
	return nil
}

func (w *Writer) add(path string, dir bool, data []byte, a Attrs) (*wnode, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	parent := w.root
	for _, p := range parts[:len(parts)-1] {
		if parent = child(parent, p); parent == nil || !parent.dir {
			return nil, fmt.Errorf("%w: no storage %q on the way to %q", ErrArgument, p, path)
		}
	}
	name := parts[len(parts)-1]
	if err := validName(name); err != nil {
		return nil, err
	}
	if child(parent, name) != nil {
		return nil, fmt.Errorf("%w: %q exists already", ErrArgument, path)
	}
	if w.entries+1 > w.maxEntries || int64(len(data)) > w.maxBytes-w.bytes {
		return nil, fmt.Errorf("%w: %q would exceed the Writer's limits (%d entries, %d bytes)", ErrLimit, path, w.maxEntries, w.maxBytes)
	}
	n := &wnode{name: name, dir: dir, data: data, attrs: a}
	parent.children = append(parent.children, n)
	w.entries++
	w.bytes += int64(len(data))
	return n, nil
}

func child(n *wnode, name string) *wnode {
	want := upper(name)
	for _, c := range n.children {
		if upper(c.name) == want {
			return c
		}
	}
	return nil
}

func filetimeOf(t time.Time) uint64 {
	const epochDiff = 11644473600
	s := t.Unix() + epochDiff
	if t.IsZero() || s < 0 {
		return 0
	}
	return uint64(s)*10_000_000 + uint64(t.Nanosecond()/100)
}

// less is the order of siblings in a directory tree: shorter names first, then
// code point by upper-cased code point.
func less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(upper(a))), utf16.Encode([]rune(upper(b)))
	if len(ua) != len(ub) {
		return len(ua) < len(ub)
	}
	return slices.Compare(ua, ub) < 0
}

type wentry struct {
	n                  *wnode
	left, right, child uint32
	start              uint32
	size               uint64
	kind               byte
}

// WriteTo writes the compound file and returns the number of bytes written.
func (w *Writer) WriteTo(dst io.Writer) (int64, error) {
	if w.version != 3 && w.version != 4 {
		return 0, fmt.Errorf("%w: version %d (3 or 4)", ErrArgument, w.version)
	}
	le := binary.LittleEndian
	ssize, shift := 512, uint16(9)
	if w.version == 4 {
		ssize, shift = 4096, 12
	}
	secs := [][]byte{}
	fat := []uint32{}
	newSector := func() uint32 {
		secs = append(secs, make([]byte, ssize))
		fat = append(fat, freeSect)
		return uint32(len(secs) - 1)
	}
	alloc := func(data []byte) uint32 {
		if len(data) == 0 {
			return endOfChain
		}
		first, prev := endOfChain, endOfChain
		for off := 0; off < len(data); off += ssize {
			id := newSector()
			if w.gaps {
				newSector()
			}
			copy(secs[id], data[off:])
			if prev == endOfChain {
				first = id
			} else {
				fat[prev] = id
			}
			fat[id] = endOfChain
			prev = id
		}
		return first
	}

	// Directory entries, breadth first, children in sibling-tree order.
	ents := []*wentry{{n: w.root, kind: byte(KindRoot), left: noStream, right: noStream, child: noStream}}
	w.layout = Layout{EntryIdx: map[string]int{}}
	for i := 0; i < len(ents); i++ {
		e := ents[i]
		if !e.n.dir || len(e.n.children) == 0 {
			continue
		}
		kids := append([]*wnode(nil), e.n.children...)
		sort.Slice(kids, func(x, y int) bool { return less(kids[x].name, kids[y].name) })
		base := len(ents)
		for _, k := range kids {
			f := &wentry{n: k, kind: byte(KindStream), left: noStream, right: noStream, child: noStream}
			if k.dir {
				f.kind = byte(KindStorage)
			}
			w.layout.EntryIdx[k.name] = len(ents)
			ents = append(ents, f)
		}
		var tree func(lo, hi int) uint32
		tree = func(lo, hi int) uint32 {
			if lo >= hi {
				return noStream
			}
			mid := (lo + hi) / 2
			ents[base+mid].left = tree(lo, mid)
			ents[base+mid].right = tree(mid+1, hi)
			return uint32(base + mid)
		}
		e.child = tree(0, len(kids))
	}
	// Streams: small ones into the mini stream, the others in the FAT.
	var mini []byte
	var miniFAT []uint32
	for _, e := range ents[1:] {
		if e.kind != byte(KindStream) {
			continue
		}
		e.size = uint64(len(e.n.data))
		switch {
		case len(e.n.data) == 0:
			e.start = endOfChain
		case len(e.n.data) < miniCutoff:
			e.start = uint32(len(mini) / miniSectorSize)
			for off := 0; off < len(e.n.data); off += miniSectorSize {
				id := uint32(len(mini) / miniSectorSize)
				mini = append(mini, make([]byte, miniSectorSize)...)
				copy(mini[int(id)*miniSectorSize:], e.n.data[off:])
				miniFAT = append(miniFAT, id+1)
			}
			miniFAT[len(miniFAT)-1] = endOfChain
		default:
			e.start = alloc(e.n.data)
		}
	}
	ents[0].size = uint64(len(mini))
	ents[0].start = alloc(mini)
	miniBytes := make([]byte, 0, len(miniFAT)*4)
	for _, v := range miniFAT {
		miniBytes = le.AppendUint32(miniBytes, v)
	}
	// MS-CFB: unused FAT entries are FREESECT, so the last mini FAT sector is
	// padded with FREESECT, not zeros (zero is a valid sector number).
	for len(miniBytes)%ssize != 0 {
		miniBytes = le.AppendUint32(miniBytes, freeSect)
	}
	firstMini := alloc(miniBytes)
	nMini := uint32(len(miniBytes) / ssize)
	// The directory, padded with unallocated entries to a whole sector.
	dir := make([]byte, 0, len(ents)*dirEntrySize)
	for _, e := range ents {
		var d [dirEntrySize]byte
		u := utf16.Encode([]rune(e.n.name))
		for i, c := range u {
			le.PutUint16(d[2*i:], c)
		}
		le.PutUint16(d[64:], uint16(2*len(u)+2))
		d[66], d[67] = e.kind, 1 // object type, black
		le.PutUint32(d[68:], e.left)
		le.PutUint32(d[72:], e.right)
		le.PutUint32(d[76:], e.child)
		copy(d[80:96], e.n.attrs.CLSID[:])
		le.PutUint32(d[96:], e.n.attrs.StateBits)
		le.PutUint64(d[100:], filetimeOf(e.n.attrs.Created))
		le.PutUint64(d[108:], filetimeOf(e.n.attrs.Modified))
		le.PutUint32(d[116:], e.start)
		le.PutUint64(d[120:], e.size)
		dir = append(dir, d[:]...)
	}
	for len(dir)%ssize != 0 {
		var d [dirEntrySize]byte
		le.PutUint32(d[68:], noStream)
		le.PutUint32(d[72:], noStream)
		le.PutUint32(d[76:], noStream)
		dir = append(dir, d[:]...)
	}
	dirSector := alloc(dir)
	nDir := uint32(len(dir) / ssize)
	// FAT and DIFAT sectors, which count themselves.
	per := ssize / 4
	nFAT, nDIFAT := 1, 0
	for {
		nDIFAT = 0
		if nFAT > difatInHeader {
			nDIFAT = (nFAT - difatInHeader + per - 2) / (per - 1)
		}
		if len(secs)+nFAT+nDIFAT <= nFAT*per {
			break
		}
		nFAT++
	}
	var fatIDs, difIDs []uint32
	for i := 0; i < nFAT; i++ {
		id := newSector()
		fat[id] = fatSect
		fatIDs = append(fatIDs, id)
	}
	for i := 0; i < nDIFAT; i++ {
		id := newSector()
		fat[id] = difSect
		difIDs = append(difIDs, id)
	}
	for len(fat) < nFAT*per {
		fat = append(fat, freeSect)
	}
	for i, id := range fatIDs {
		for j := 0; j < per; j++ {
			le.PutUint32(secs[id][4*j:], fat[i*per+j])
		}
	}
	hdr := make([]byte, ssize)
	copy(hdr, signature[:])
	le.PutUint16(hdr[24:], 0x3E)
	le.PutUint16(hdr[26:], uint16(w.version))
	le.PutUint16(hdr[28:], 0xFFFE)
	le.PutUint16(hdr[30:], shift)
	le.PutUint16(hdr[32:], 6)
	if w.version == 4 {
		le.PutUint32(hdr[40:], nDir)
	}
	le.PutUint32(hdr[44:], uint32(nFAT))
	le.PutUint32(hdr[48:], dirSector)
	le.PutUint32(hdr[56:], miniCutoff)
	le.PutUint32(hdr[60:], firstMini)
	le.PutUint32(hdr[64:], nMini)
	le.PutUint32(hdr[68:], endOfChain)
	le.PutUint32(hdr[72:], uint32(nDIFAT))
	for i := 0; i < difatInHeader; i++ {
		v := freeSect
		if i < nFAT {
			v = fatIDs[i]
		}
		le.PutUint32(hdr[76+4*i:], v)
	}
	if nDIFAT > 0 {
		le.PutUint32(hdr[68:], difIDs[0])
		rest := fatIDs[difatInHeader:]
		for i, id := range difIDs {
			sec := secs[id]
			for j := 0; j < per-1; j++ {
				v := freeSect
				if k := i*(per-1) + j; k < len(rest) {
					v = rest[k]
				}
				le.PutUint32(sec[4*j:], v)
			}
			next := endOfChain
			if i+1 < len(difIDs) {
				next = difIDs[i+1]
			}
			le.PutUint32(sec[4*(per-1):], next)
		}
	}
	w.layout.DirSector = dirSector
	w.layout.DirOffset = int64(dirSector+1) * int64(ssize)
	w.layout.FATOffset = int64(fatIDs[0]+1) * int64(ssize)
	total, err := dst.Write(hdr)
	for _, s := range secs {
		if err != nil {
			break
		}
		var n int
		n, err = dst.Write(s)
		total += n
	}
	return int64(total), err
}

// Layout returns where the last WriteTo put the structures.
func (w *Writer) Layout() Layout { return w.layout }
