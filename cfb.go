// Package cfb reads Microsoft Compound File Binary (MS-CFB, "OLE2")
// containers: the format of .doc/.xls/.msg files, .msi installers and Prim'X
// .zed archives.
//
// It reads version 3 (512-byte sectors) and version 4 (4096-byte sectors)
// files: the FAT, the DIFAT, the mini FAT and the mini stream, and the
// red-black directory trees. Writing is out of scope.
//
// The input is untrusted. Every sector chain is bounded by the number of
// sectors the file can hold and checked for cycles, every declared size is
// refused when it exceeds what the file holds, and no allocation is sized from
// a header field without first being compared with the file size.
//
// It has no dependency outside the standard library. It was written for the
// go-fde/zed reader and moved here unchanged.
package cfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
)

var (
	// ErrFormat reports a container that does not follow MS-CFB.
	ErrFormat = errors.New("cfb: invalid compound file")
	// ErrLimit reports a size above a limit the caller set.
	ErrLimit = errors.New("cfb: size limit exceeded")
)

const (
	headerSize     = 512
	miniSectorSize = 64
	miniCutoff     = 4096
	dirEntrySize   = 128
	difatInHeader  = 109

	freeSect   uint32 = 0xFFFFFFFF
	endOfChain uint32 = 0xFFFFFFFE
	noStream   uint32 = 0xFFFFFFFF
)

var signature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Kind is the object type of a directory entry.
type Kind uint8

// Object types (MS-CFB, Directory Entry).
const (
	KindStorage Kind = 1
	KindStream  Kind = 2
	KindRoot    Kind = 5
)

// Entry is a storage or stream of the container.
type Entry struct {
	Name      string
	Kind      Kind
	Size      int64 // stream size; mini stream size for the root
	CLSID     [16]byte
	StateBits uint32
	Created   time.Time // zero when not recorded
	Modified  time.Time // zero when not recorded
	// Children are the entries of a storage, in red-black tree order
	// (shorter names first, then upper-cased code points).
	Children []*Entry

	start  uint32
	once   sync.Once
	byName map[string]*Entry
}

// IsDir reports whether the entry is a storage (or the root).
func (e *Entry) IsDir() bool { return e.Kind != KindStream }

// File is an open compound file.
type File struct {
	r        io.ReaderAt
	ssize    int64
	nSectors int64
	version  uint16
	fat      []uint32
	miniFAT  []uint32
	mini     *Stream // the mini stream, nil when the root has none
	root     *Entry
}

// Version returns the major version, 3 or 4.
func (f *File) Version() int { return int(f.version) }

// Root returns the root storage.
func (f *File) Root() *Entry { return f.root }

// Open parses the container held by r, which is size bytes long.
func Open(r io.ReaderAt, size int64) (*File, error) {
	f := &File{r: r}
	var h [headerSize]byte
	if size < headerSize {
		return nil, fmt.Errorf("%w: %d bytes is shorter than the header", ErrFormat, size)
	}
	if err := f.readFull(h[:], 0); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if [8]byte(h[0:8]) != signature {
		return nil, fmt.Errorf("%w: bad signature", ErrFormat)
	}
	f.version = le.Uint16(h[26:])
	shift := le.Uint16(h[30:])
	switch {
	case le.Uint16(h[28:]) != 0xFFFE:
		return nil, fmt.Errorf("%w: bad byte order mark", ErrFormat)
	case f.version == 3 && shift == 9, f.version == 4 && shift == 12:
	default:
		return nil, fmt.Errorf("%w: version %d with sector shift %d", ErrFormat, f.version, shift)
	}
	if le.Uint16(h[32:]) != 6 || le.Uint32(h[56:]) != miniCutoff {
		return nil, fmt.Errorf("%w: unsupported mini stream parameters", ErrFormat)
	}
	f.ssize = 1 << shift
	// Sector 0 starts after the first sector-sized block, which holds the header.
	f.nSectors = (size - 1) / f.ssize
	if err := f.loadFAT(h[:]); err != nil {
		return nil, err
	}
	if err := f.loadDirectory(le.Uint32(h[48:])); err != nil {
		return nil, err
	}
	if err := f.loadMini(le.Uint32(h[60:]), int64(le.Uint32(h[64:]))); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) readFull(p []byte, off int64) error {
	n, err := f.r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: truncated at offset %d", ErrFormat, off)
	}
	return err
}

func (f *File) sector(id uint32) ([]byte, error) {
	b := make([]byte, f.ssize)
	if err := f.readFull(b, (int64(id)+1)*f.ssize); err != nil {
		return nil, err
	}
	return b, nil
}

func (f *File) loadFAT(h []byte) error {
	le := binary.LittleEndian
	nFAT, nDIFAT := int64(le.Uint32(h[44:])), int64(le.Uint32(h[72:]))
	if nFAT > f.nSectors || nDIFAT > f.nSectors {
		return fmt.Errorf("%w: %d FAT and %d DIFAT sectors in a file of %d sectors", ErrFormat, nFAT, nDIFAT, f.nSectors)
	}
	ids := make([]uint32, 0, nFAT)
	add := func(b []byte) {
		for ; len(b) >= 4 && int64(len(ids)) < nFAT; b = b[4:] {
			if id := le.Uint32(b); id != freeSect {
				ids = append(ids, id)
			}
		}
	}
	add(h[76 : 76+4*difatInHeader])
	next := le.Uint32(h[68:])
	for i := int64(0); i < nDIFAT; i++ {
		if int64(next) >= f.nSectors {
			return fmt.Errorf("%w: DIFAT sector %#x out of range", ErrFormat, next)
		}
		b, err := f.sector(next)
		if err != nil {
			return err
		}
		add(b[:f.ssize-4])
		next = le.Uint32(b[f.ssize-4:])
	}
	if int64(len(ids)) != nFAT {
		return fmt.Errorf("%w: %d FAT sectors declared, %d located", ErrFormat, nFAT, len(ids))
	}
	f.fat = make([]uint32, 0, nFAT*f.ssize/4)
	for _, id := range ids {
		if int64(id) >= f.nSectors {
			return fmt.Errorf("%w: FAT sector %#x out of range", ErrFormat, id)
		}
		b, err := f.sector(id)
		if err != nil {
			return err
		}
		for ; len(b) > 0; b = b[4:] {
			f.fat = append(f.fat, le.Uint32(b))
		}
	}
	return nil
}

// walk follows a chain through table. need < 0 walks to ENDOFCHAIN, otherwise
// exactly need sectors. Every sector must be below limit and met once.
func walk(table []uint32, start uint32, need, limit int64) ([]uint32, error) {
	limit = min(limit, int64(len(table)))
	if need > limit {
		return nil, fmt.Errorf("%w: %d sectors wanted, %d available", ErrFormat, need, limit)
	}
	seen := make([]uint64, (limit+63)/64) // a bit per sector, not a byte
	var out []uint32
	for s := start; need < 0 && s != endOfChain || int64(len(out)) < need; s = table[s] {
		if int64(s) >= limit || seen[s/64]&(1<<(s%64)) != 0 {
			return nil, fmt.Errorf("%w: bad sector chain at %#x", ErrFormat, s)
		}
		seen[s/64] |= 1 << (s % 64)
		out = append(out, s)
	}
	return out, nil
}

type rawEntry struct {
	name               string
	kind               Kind
	left, right, child uint32
	clsid              [16]byte
	state              uint32
	created, modified  time.Time
	start              uint32
	size               int64
}

func filetime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	const epochDiff = 11644473600 // seconds from 1601 to 1970
	return time.Unix(int64(v/10_000_000)-epochDiff, int64(v%10_000_000)*100).UTC()
}

func (f *File) loadDirectory(first uint32) error {
	chain, err := walk(f.fat, first, -1, f.nSectors)
	if err != nil {
		return err
	}
	le := binary.LittleEndian
	var raw []rawEntry
	for _, id := range chain {
		b, err := f.sector(id)
		if err != nil {
			return err
		}
		for ; len(b) >= dirEntrySize; b = b[dirEntrySize:] {
			e := rawEntry{kind: Kind(b[66]), left: le.Uint32(b[68:]), right: le.Uint32(b[72:]), child: le.Uint32(b[76:]),
				state: le.Uint32(b[96:]), created: filetime(le.Uint64(b[100:])), modified: filetime(le.Uint64(b[108:])),
				start: le.Uint32(b[116:]), size: int64(le.Uint64(b[120:]))}
			copy(e.clsid[:], b[80:96])
			if f.version == 3 {
				e.size &= 0xFFFFFFFF // older writers left the high half uninitialised
			}
			switch e.kind {
			case 0:
			case KindStorage, KindStream, KindRoot:
				n := int(le.Uint16(b[64:]))
				if n < 2 || n > 64 || n%2 != 0 {
					return fmt.Errorf("%w: directory entry name length %d", ErrFormat, n)
				}
				u := make([]uint16, n/2-1)
				for i := range u {
					u[i] = le.Uint16(b[2*i:])
				}
				e.name = string(utf16.Decode(u))
			default:
				return fmt.Errorf("%w: object type %d", ErrFormat, e.kind)
			}
			if e.size < 0 {
				return fmt.Errorf("%w: stream size above 2^63", ErrFormat)
			}
			raw = append(raw, e)
		}
	}
	if len(raw) == 0 || raw[0].kind != KindRoot {
		return fmt.Errorf("%w: entry 0 is not the root storage", ErrFormat)
	}
	return f.buildTree(raw)
}

func (f *File) buildTree(raw []rawEntry) error {
	seen := make([]bool, len(raw))
	seen[0] = true
	toEntry := func(r *rawEntry) *Entry {
		return &Entry{Name: r.name, Kind: r.kind, Size: r.size, CLSID: r.clsid, StateBits: r.state,
			Created: r.created, Modified: r.modified, start: r.start}
	}
	f.root = toEntry(&raw[0])
	type item struct {
		e   *Entry
		idx int
	}
	queue := []item{{f.root, 0}}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		// In-order walk of the sibling tree rooted at the child pointer.
		var stack []uint32
		for cur := raw[it.idx].child; cur != noStream || len(stack) > 0; {
			for cur != noStream {
				if int64(cur) >= int64(len(raw)) || seen[cur] {
					return fmt.Errorf("%w: directory entry %#x is out of range or reached twice", ErrFormat, cur)
				}
				seen[cur] = true
				stack = append(stack, cur)
				cur = raw[cur].left
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			r := &raw[n]
			if r.kind != KindStorage && r.kind != KindStream {
				return fmt.Errorf("%w: entry %d has type %d inside a storage", ErrFormat, n, r.kind)
			}
			c := toEntry(r)
			it.e.Children = append(it.e.Children, c)
			if r.kind == KindStorage {
				queue = append(queue, item{c, int(n)})
			}
			cur = r.right
		}
	}
	return nil
}

func (f *File) loadMini(first uint32, n int64) error {
	if f.root.Size == 0 {
		return nil
	}
	ms, err := f.openRegular(f.root.start, f.root.Size)
	if err != nil {
		return err
	}
	f.mini = ms
	chain, err := walk(f.fat, first, -1, f.nSectors)
	if err != nil {
		return err
	}
	if int64(len(chain)) != n {
		return fmt.Errorf("%w: %d mini FAT sectors declared, chain has %d", ErrFormat, n, len(chain))
	}
	le := binary.LittleEndian
	for _, id := range chain {
		b, err := f.sector(id)
		if err != nil {
			return err
		}
		for ; len(b) > 0; b = b[4:] {
			f.miniFAT = append(f.miniFAT, le.Uint32(b))
		}
	}
	return nil
}

// ceilDiv is a/b rounded up, without the overflow of (a+b-1)/b.
func ceilDiv(a, b int64) int64 {
	return a/b + min(a%b, 1)
}

// upper maps each code point to upper case on its own, as the directory
// ordering rule asks. Surrogate halves cannot occur here: a lone surrogate
// has already become U+FFFD when the name was decoded.
func upper(s string) string { return strings.Map(unicode.ToUpper, s) }

// Child returns the child of e whose name equals name, ignoring case as
// MS-CFB defines it.
func (e *Entry) Child(name string) *Entry {
	e.once.Do(func() { // index once: looking up every entry stays linear
		e.byName = make(map[string]*Entry, len(e.Children))
		for _, c := range e.Children {
			if _, dup := e.byName[upper(c.Name)]; !dup {
				e.byName[upper(c.Name)] = c
			}
		}
	})
	return e.byName[upper(name)]
}

// Lookup resolves a slash-separated path from the root. Empty elements are
// ignored. It returns nil when nothing matches.
func (f *File) Lookup(path string) *Entry {
	e := f.root
	for _, p := range strings.Split(path, "/") {
		if p == "" {
			continue
		}
		if e = e.Child(p); e == nil {
			return nil
		}
	}
	return e
}

// Stream is the content of a stream entry. It implements io.ReaderAt.
type Stream struct {
	f     *File
	size  int64
	chain []uint32
	mini  bool
}

// Size returns the stream length in bytes.
func (s *Stream) Size() int64 { return s.size }

// Open returns the content of a stream entry.
func (f *File) Open(e *Entry) (*Stream, error) {
	if e.Kind != KindStream {
		return nil, fmt.Errorf("cfb: %q is not a stream", e.Name)
	}
	if e.Size < miniCutoff {
		return f.openMini(e.start, e.Size)
	}
	return f.openRegular(e.start, e.Size)
}

func (f *File) openRegular(start uint32, size int64) (*Stream, error) {
	chain, err := walk(f.fat, start, ceilDiv(size, f.ssize), f.nSectors)
	if err != nil {
		return nil, err
	}
	return &Stream{f: f, size: size, chain: chain}, nil
}

func (f *File) openMini(start uint32, size int64) (*Stream, error) {
	if size == 0 {
		return &Stream{f: f, mini: true}, nil
	}
	if f.mini == nil {
		return nil, fmt.Errorf("%w: mini stream data but no mini stream", ErrFormat)
	}
	chain, err := walk(f.miniFAT, start, ceilDiv(size, miniSectorSize), ceilDiv(f.mini.size, miniSectorSize))
	if err != nil {
		return nil, err
	}
	return &Stream{f: f, size: size, chain: chain, mini: true}, nil
}

// ReadAt implements io.ReaderAt.
func (s *Stream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("cfb: negative offset")
	}
	if off >= s.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if rest := s.size - off; want > rest {
		want = rest
	}
	unit := s.f.ssize
	if s.mini {
		unit = miniSectorSize
	}
	var done int64
	for done < want {
		pos := off + done
		i, within := pos/unit, pos%unit
		run := int64(1)
		if !s.mini {
			// Read contiguous sectors in one call.
			for i+run < int64(len(s.chain)) && s.chain[i+run] == s.chain[i+run-1]+1 && run*unit-within < want-done {
				run++
			}
		}
		n := min(run*unit-within, want-done)
		buf := p[done : done+n]
		var err error
		if s.mini {
			// The mini stream may be shorter than its mini FAT chains say.
			var got int
			got, err = s.f.mini.ReadAt(buf, int64(s.chain[i])*miniSectorSize+within)
			if got < len(buf) && (err == nil || errors.Is(err, io.EOF)) {
				err = fmt.Errorf("%w: mini stream is shorter than its sector chain", ErrFormat)
			}
		} else {
			err = s.f.readFull(buf, (int64(s.chain[i])+1)*unit+within)
		}
		if err != nil {
			return int(done), err
		}
		done += n
	}
	if done < int64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}

// ReadAll returns the whole stream, refusing with ErrLimit above max bytes.
func (f *File) ReadAll(e *Entry, max int64) ([]byte, error) {
	if e.Size > max {
		return nil, fmt.Errorf("%w: stream %q is %d bytes, limit %d", ErrLimit, e.Name, e.Size, max)
	}
	s, err := f.Open(e)
	if err != nil {
		return nil, err
	}
	b := make([]byte, s.size)
	// ReadAt answers io.EOF only for an empty stream; a stream shorter than its
	// size is an ErrFormat error, so no zero-filled tail is returned.
	if _, err := s.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b, nil
}
