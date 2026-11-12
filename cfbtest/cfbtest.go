// Package cfbtest builds compound files for tests. It is a test aid: the cfb
// package itself does not write compound files.
package cfbtest

import (
	"encoding/binary"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
)

const (
	freeSect   uint32 = 0xFFFFFFFF
	endOfChain uint32 = 0xFFFFFFFE
	noStream   uint32 = 0xFFFFFFFF
	miniCutoff        = 4096
	difatInHdr        = 109
	dirEntry          = 128
)

var signature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

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

// Layout tells where the builder put things, for tests that corrupt a file.
type Layout struct {
	DirOff    int64 // byte offset of the directory
	FatOff    int64 // byte offset of the first FAT sector
	DirSector uint32
	EntryIdx  map[string]int // name -> directory entry index
}

type builder struct {
	ssize int
	secs  [][]byte
	fat   []uint32
	gappy bool
}

func (b *builder) newSector() uint32 {
	b.secs = append(b.secs, make([]byte, b.ssize))
	b.fat = append(b.fat, freeSect)
	return uint32(len(b.secs) - 1)
}

// alloc stores data in a chain and returns its first sector.
func (b *builder) alloc(data []byte) uint32 {
	if len(data) == 0 {
		return endOfChain
	}
	first, prev := endOfChain, endOfChain
	for off := 0; off < len(data); off += b.ssize {
		id := b.newSector()
		if b.gappy {
			b.newSector() // left free: makes the chain non-contiguous
		}
		copy(b.secs[id], data[off:])
		if prev == endOfChain {
			first = id
		} else {
			b.fat[prev] = id
		}
		b.fat[id] = endOfChain
		prev = id
	}
	return first
}

func upper(s string) string { return strings.Map(unicode.ToUpper, s) }

func less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(upper(a))), utf16.Encode([]rune(upper(b)))
	if len(ua) != len(ub) {
		return len(ua) < len(ub)
	}
	for i := range ua {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return false
}

type flat struct {
	n                  *Node
	left, right, child uint32
	start              uint32
	size               uint64
	kind               byte
}

// Build returns a compound file of the given major version (3 or 4). With
// gappy, a free sector follows each data sector so chains are not contiguous.
func Build(version int, root *Node, gappy bool) ([]byte, Layout) {
	le := binary.LittleEndian
	b := &builder{ssize: 512, gappy: gappy}
	shift := uint16(9)
	if version == 4 {
		b.ssize, shift = 4096, 12
	}
	// Directory entries in breadth-first order.
	ents := []*flat{{n: root, kind: 5, left: noStream, right: noStream, child: noStream}}
	lay := Layout{EntryIdx: map[string]int{}}
	for i := 0; i < len(ents); i++ {
		e := ents[i]
		if !e.n.Dir || len(e.n.Children) == 0 {
			continue
		}
		kids := append([]*Node(nil), e.n.Children...)
		sort.Slice(kids, func(x, y int) bool { return less(kids[x].Name, kids[y].Name) })
		base := len(ents)
		for _, k := range kids {
			f := &flat{n: k, kind: 2, left: noStream, right: noStream, child: noStream}
			if k.Dir {
				f.kind = 1
			}
			lay.EntryIdx[k.Name] = len(ents)
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
	// Streams: small ones go to the mini stream.
	var mini []byte
	var miniFAT []uint32
	for _, e := range ents[1:] {
		if e.kind != 2 {
			continue
		}
		e.size = uint64(len(e.n.Data))
		switch {
		case len(e.n.Data) == 0:
			e.start = endOfChain
		case len(e.n.Data) < miniCutoff:
			e.start = uint32(len(mini) / 64)
			for off := 0; off < len(e.n.Data); off += 64 {
				id := uint32(len(mini) / 64)
				mini = append(mini, make([]byte, 64)...)
				copy(mini[id*64:], e.n.Data[off:])
				miniFAT = append(miniFAT, id+1)
			}
			miniFAT[len(miniFAT)-1] = endOfChain
		default:
			e.start = b.alloc(e.n.Data)
		}
	}
	ents[0].size = uint64(len(mini))
	ents[0].start = b.alloc(mini)
	miniBytes := make([]byte, 0, len(miniFAT)*4)
	for _, v := range miniFAT {
		miniBytes = le.AppendUint32(miniBytes, v)
	}
	firstMini := b.alloc(miniBytes)
	nMini := uint32((len(miniBytes) + b.ssize - 1) / b.ssize)
	// Directory.
	dir := make([]byte, 0, len(ents)*dirEntry)
	for _, e := range ents {
		var d [dirEntry]byte
		u := utf16.Encode([]rune(e.n.Name))
		for i, c := range u {
			le.PutUint16(d[2*i:], c)
		}
		le.PutUint16(d[64:], uint16(2*len(u)+2))
		d[66], d[67] = e.kind, 1
		le.PutUint32(d[68:], e.left)
		le.PutUint32(d[72:], e.right)
		le.PutUint32(d[76:], e.child)
		le.PutUint64(d[100:], e.n.Created)
		le.PutUint64(d[108:], e.n.Modified)
		le.PutUint32(d[116:], e.start)
		le.PutUint64(d[120:], e.size)
		dir = append(dir, d[:]...)
	}
	for len(dir)%b.ssize != 0 { // unallocated entries pad the last sector
		var d [dirEntry]byte
		le.PutUint32(d[68:], noStream)
		le.PutUint32(d[72:], noStream)
		le.PutUint32(d[76:], noStream)
		dir = append(dir, d[:]...)
	}
	dirSector := b.alloc(dir)
	// FAT and DIFAT sectors.
	per := b.ssize / 4
	nFAT, nDIFAT := 1, 0
	for {
		nDIFAT = 0
		if nFAT > difatInHdr {
			nDIFAT = (nFAT - difatInHdr + per - 2) / (per - 1)
		}
		if len(b.secs)+nFAT+nDIFAT <= nFAT*per {
			break
		}
		nFAT++
	}
	var fatIDs, difIDs []uint32
	for i := 0; i < nFAT; i++ {
		id := b.newSector()
		b.fat[id] = 0xFFFFFFFD
		fatIDs = append(fatIDs, id)
	}
	for i := 0; i < nDIFAT; i++ {
		id := b.newSector()
		b.fat[id] = 0xFFFFFFFC
		difIDs = append(difIDs, id)
	}
	for len(b.fat) < nFAT*per {
		b.fat = append(b.fat, freeSect)
	}
	for i, id := range fatIDs {
		for j := 0; j < per; j++ {
			le.PutUint32(b.secs[id][4*j:], b.fat[i*per+j])
		}
	}
	hdr := make([]byte, b.ssize)
	copy(hdr, signature[:])
	le.PutUint16(hdr[24:], 0x3E)
	le.PutUint16(hdr[26:], uint16(version))
	le.PutUint16(hdr[28:], 0xFFFE)
	le.PutUint16(hdr[30:], shift)
	le.PutUint16(hdr[32:], 6)
	le.PutUint32(hdr[44:], uint32(nFAT))
	le.PutUint32(hdr[48:], dirSector)
	le.PutUint32(hdr[56:], miniCutoff)
	le.PutUint32(hdr[60:], firstMini)
	le.PutUint32(hdr[64:], nMini)
	le.PutUint32(hdr[68:], endOfChain)
	le.PutUint32(hdr[72:], uint32(nDIFAT))
	for i := 0; i < difatInHdr; i++ {
		v := freeSect
		if i < nFAT {
			v = fatIDs[i]
		}
		le.PutUint32(hdr[76+4*i:], v)
	}
	if nDIFAT > 0 {
		le.PutUint32(hdr[68:], difIDs[0])
		rest := fatIDs[difatInHdr:]
		for i, id := range difIDs {
			sec := b.secs[id]
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
	out := hdr
	for _, s := range b.secs {
		out = append(out, s...)
	}
	lay.DirSector = dirSector
	lay.DirOff = int64(dirSector+1) * int64(b.ssize)
	lay.FatOff = int64(fatIDs[0]+1) * int64(b.ssize)
	return out, lay
}
