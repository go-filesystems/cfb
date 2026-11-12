package cfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pattern(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 1))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func sampleTree() *node {
	t := storage("Root Entry",
		stream("\x05SummaryInformation", pattern(300, 1)),
		stream("empty", nil),
		stream("small", pattern(63, 2)),
		stream("edge4095", pattern(4095, 3)),
		stream("edge4096", pattern(4096, 4)),
		stream("big", pattern(40000, 5)),
		storage("Dir",
			stream("Inner", pattern(5000, 6)),
			stream("zz", pattern(70, 7)),
			storage("Deep", stream("leaf", []byte("hello"))),
		),
		storage("EmptyDir"),
		stream("a longer name than the rest", pattern(10, 8)),
	)
	return t
}

func open(t testing.TB, data []byte) *File {
	t.Helper()
	f, err := Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRoundTrip(t *testing.T) {
	for _, version := range []int{3, 4} {
		for _, gappy := range []bool{false, true} {
			tree := sampleTree()
			data, _ := build(version, tree, gappy)
			f := open(t, data)
			if f.Version() != version {
				t.Fatalf("version %d", f.Version())
			}
			check := func(path string, want []byte) {
				t.Helper()
				e := f.Lookup(path)
				if e == nil {
					t.Fatalf("v%d %s: missing", version, path)
				}
				got, err := f.ReadAll(e, 1<<20)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("v%d gappy=%v %s: err=%v equal=%v", version, gappy, path, err, bytes.Equal(got, want))
				}
			}
			for _, k := range tree.Children {
				if !k.Dir {
					check(k.Name, k.Data)
				}
			}
			check("dir/inner", pattern(5000, 6)) // case-insensitive
			check("/Dir//ZZ", pattern(70, 7))
			check("Dir/Deep/leaf", []byte("hello"))
			if f.Lookup("Dir/nothing") != nil || f.Lookup("big/x") != nil {
				t.Fatal("lookup of a missing name succeeded")
			}
			if f.Lookup("") != f.Root() || !f.Root().IsDir() || f.Lookup("big").IsDir() {
				t.Fatal("root / IsDir")
			}
			if len(f.Lookup("EmptyDir").Children) != 0 || len(f.Lookup("Dir").Children) != 3 {
				t.Fatal("children")
			}
			// Tree order: shorter names first.
			names := ""
			for _, c := range f.Lookup("Dir").Children {
				names += c.Name + ","
			}
			if names != "zz,Inner,Deep," && names != "zz,Deep,Inner," {
				t.Fatalf("order %q", names)
			}
		}
	}
}

func TestReadAtVariants(t *testing.T) {
	want := pattern(40000, 5)
	for _, gappy := range []bool{false, true} {
		data, _ := build(3, sampleTree(), gappy)
		f := open(t, data)
		s, err := f.Open(f.Lookup("big"))
		if err != nil {
			t.Fatal(err)
		}
		if s.Size() != 40000 {
			t.Fatal(s.Size())
		}
		r := rand.New(rand.NewPCG(9, 9))
		for i := 0; i < 300; i++ {
			off := r.IntN(40000)
			n := r.IntN(3000)
			buf := make([]byte, n)
			got, err := s.ReadAt(buf, int64(off))
			end := min(off+n, 40000)
			if got != end-off || !bytes.Equal(buf[:got], want[off:end]) {
				t.Fatalf("off %d n %d: got %d", off, n, got)
			}
			if (end-off < n) != (err == io.EOF) {
				t.Fatalf("off %d n %d: err %v", off, n, err)
			}
		}
		// Mini stream reads across sector boundaries.
		m, _ := f.Open(f.Lookup("small"))
		buf := make([]byte, 10)
		if n, err := m.ReadAt(buf, 60); n != 3 || err != io.EOF {
			t.Fatalf("mini tail %d %v", n, err)
		}
		if n, err := m.ReadAt(buf, 63); n != 0 || err != io.EOF {
			t.Fatalf("mini end %d %v", n, err)
		}
		if _, err := m.ReadAt(buf, -1); err == nil {
			t.Fatal("negative offset accepted")
		}
		if n, err := m.ReadAt(buf[:5], 10); n != 5 || err != nil {
			t.Fatalf("mini mid %d %v", n, err)
		}
	}
}

func TestDIFAT(t *testing.T) {
	big := pattern(8<<20, 11) // more than 109 FAT sectors of 512-byte sectors
	data, _ := build(3, storage("Root Entry", stream("huge", big), stream("tiny", []byte("x"))), false)
	f := open(t, data)
	if binary.LittleEndian.Uint32(data[72:]) == 0 {
		t.Fatal("the builder produced no DIFAT sector")
	}
	got, err := f.ReadAll(f.Lookup("huge"), 16<<20)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("huge stream: %v", err)
	}
	if got, _ := f.ReadAll(f.Lookup("tiny"), 10); string(got) != "x" {
		t.Fatal("tiny")
	}
}

func TestMetadata(t *testing.T) {
	tree := storage("Root Entry", &node{Name: "dated", Dir: true, Created: 132_000_000_000_000_000, Modified: 116_444_736_000_000_001})
	data, _ := build(3, tree, false)
	e := open(t, data).Lookup("dated")
	if !e.Created.Equal(time.Unix(132_000_000_000_000_000/10_000_000-11644473600, 0)) {
		t.Fatalf("created %v", e.Created)
	}
	if e.Modified.UnixNano() != 100 { // 1970-01-01 plus one 100 ns tick
		t.Fatalf("modified %v", e.Modified.UnixNano())
	}
	if !open(t, data).Root().Created.IsZero() {
		t.Fatal("zero FILETIME must be the zero time")
	}
}

func TestV3IgnoresStaleHighSize(t *testing.T) {
	data, lay := build(3, storage("Root Entry", stream("s", []byte("abc"))), false)
	off := lay.DirOff + int64(lay.EntryIdx["s"])*dirEntrySize
	binary.LittleEndian.PutUint32(data[off+124:], 0xDEADBEEF)
	f := open(t, data)
	if got, err := f.ReadAll(f.Lookup("s"), 100); err != nil || string(got) != "abc" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestOpenRefusals(t *testing.T) {
	le := binary.LittleEndian
	base, lay := build(3, sampleTree(), false)
	base4, lay4 := build(4, sampleTree(), false)
	ent := func(l layout, name string) int64 { return l.DirOff + int64(l.EntryIdx[name])*dirEntrySize }
	cases := []struct {
		Name string
		v4   bool
		mut  func(b []byte, l layout)
	}{
		{"signature", false, func(b []byte, _ layout) { b[0] ^= 1 }},
		{"byte order", false, func(b []byte, _ layout) { le.PutUint16(b[28:], 0xFEFF) }},
		{"v3 with shift 12", false, func(b []byte, _ layout) { le.PutUint16(b[30:], 12) }},
		{"v5", false, func(b []byte, _ layout) { le.PutUint16(b[26:], 5) }},
		{"mini shift", false, func(b []byte, _ layout) { le.PutUint16(b[32:], 7) }},
		{"cutoff", false, func(b []byte, _ layout) { le.PutUint32(b[56:], 1) }},
		{"huge FAT count", false, func(b []byte, _ layout) { le.PutUint32(b[44:], 1<<30) }},
		{"huge DIFAT count", false, func(b []byte, _ layout) { le.PutUint32(b[72:], 1<<30) }},
		{"DIFAT out of range", false, func(b []byte, _ layout) { le.PutUint32(b[72:], 1); le.PutUint32(b[68:], 0xFFFFFFF0) }},
		{"FAT count above located", false, func(b []byte, _ layout) { le.PutUint32(b[44:], 2) }},
		{"FAT sector out of range", false, func(b []byte, _ layout) { le.PutUint32(b[76:], 9999) }},
		{"directory cycle", false, func(b []byte, l layout) {
			le.PutUint32(b[l.FatOff+4*int64(l.DirSector):], l.DirSector)
		}},
		{"directory start out of range", false, func(b []byte, _ layout) { le.PutUint32(b[48:], 9999) }},
		{"no directory", false, func(b []byte, _ layout) { le.PutUint32(b[48:], endOfChain) }},
		{"entry 0 not root", false, func(b []byte, l layout) { b[l.DirOff+66] = 1 }},
		{"name length 0", false, func(b []byte, l layout) { le.PutUint16(b[ent(l, "big")+64:], 0) }},
		{"name length odd", false, func(b []byte, l layout) { le.PutUint16(b[ent(l, "big")+64:], 7) }},
		{"name length 66", false, func(b []byte, l layout) { le.PutUint16(b[ent(l, "big")+64:], 66) }},
		{"object type 3", false, func(b []byte, l layout) { b[ent(l, "big")+66] = 3 }},
		{"sibling cycle", false, func(b []byte, l layout) {
			i := uint32(l.EntryIdx["big"])
			le.PutUint32(b[ent(l, "big")+72:], i)
			le.PutUint32(b[ent(l, "big")+68:], i)
		}},
		{"sibling out of range", false, func(b []byte, l layout) { le.PutUint32(b[ent(l, "big")+72:], 5000) }},
		{"root inside a storage", false, func(b []byte, l layout) { b[ent(l, "big")+66] = 5 }},
		{"size above 2^63", true, func(b []byte, l layout) { le.PutUint64(b[ent(l, "big")+120:], 1<<63) }},
		{"mini FAT count", false, func(b []byte, _ layout) { le.PutUint32(b[64:], 9) }},
		{"mini FAT start", false, func(b []byte, _ layout) { le.PutUint32(b[60:], 9999) }},
		{"mini stream chain", false, func(b []byte, l layout) { le.PutUint32(b[l.DirOff+116:], 9999) }},
		{"mini stream size above file", false, func(b []byte, l layout) { le.PutUint64(b[l.DirOff+120:], 1<<30) }},
	}
	for _, c := range cases {
		src, l := base, lay
		if c.v4 {
			src, l = base4, lay4
		}
		b := append([]byte(nil), src...)
		c.mut(b, l)
		if _, err := Open(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	if _, err := Open(bytes.NewReader(base[:100]), 100); !errors.Is(err, ErrFormat) {
		t.Errorf("short: %v", err)
	}
	// Truncation anywhere in the file: no panic, an error or a smaller tree.
	for n := headerSize; n < len(base); n += 97 {
		if f, err := Open(bytes.NewReader(base[:n]), int64(n)); err == nil {
			for _, c := range f.Root().Children {
				if !c.IsDir() {
					f.ReadAll(c, 1<<20) //nolint:errcheck // must not panic
				}
			}
		}
	}
}

func TestStreamRefusals(t *testing.T) {
	le := binary.LittleEndian
	data, lay := build(3, sampleTree(), false)
	ent := func(name string) int64 { return lay.DirOff + int64(lay.EntryIdx[name])*dirEntrySize }

	// Chain shorter than the declared size.
	b := append([]byte(nil), data...)
	le.PutUint64(b[ent("big")+120:], 1<<20)
	f := open(t, b)
	if _, err := f.Open(f.Lookup("big")); !errors.Is(err, ErrFormat) {
		t.Errorf("long size: %v", err)
	}
	// Chain cycle in a stream.
	b = append([]byte(nil), data...)
	f = open(t, b)
	start := le.Uint32(b[ent("big")+116:])
	le.PutUint32(b[lay.FatOff+4*int64(start):], start)
	f = open(t, b)
	if _, err := f.Open(f.Lookup("big")); !errors.Is(err, ErrFormat) {
		t.Errorf("cycle: %v", err)
	}
	// Mini data but no mini stream.
	b = append([]byte(nil), data...)
	le.PutUint64(b[lay.DirOff+120:], 0)
	f = open(t, b)
	if _, err := f.Open(f.Lookup("small")); !errors.Is(err, ErrFormat) {
		t.Errorf("no mini stream: %v", err)
	}
	if _, err := f.Open(f.Lookup("empty")); err != nil {
		t.Errorf("empty stream without mini stream: %v", err)
	}
	// Mini stream chain out of range.
	b = append([]byte(nil), data...)
	le.PutUint32(b[ent("small")+116:], 9999)
	f = open(t, b)
	if _, err := f.Open(f.Lookup("small")); !errors.Is(err, ErrFormat) {
		t.Errorf("mini chain: %v", err)
	}

	f = open(t, data)
	if _, err := f.Open(f.Root()); err == nil {
		t.Error("opening a storage succeeded")
	}
	if _, err := f.ReadAll(f.Root(), 10); !errors.Is(err, ErrLimit) {
		t.Errorf("limit on root: %v", err)
	}
	if _, err := f.ReadAll(f.Lookup("big"), 100); !errors.Is(err, ErrLimit) {
		t.Errorf("limit: %v", err)
	}
	if _, err := f.ReadAll(f.Lookup("Dir"), 1<<20); err == nil || errors.Is(err, ErrLimit) {
		t.Errorf("ReadAll of a storage: %v", err)
	}
	if got, err := f.ReadAll(f.Lookup("empty"), 0); err != nil || len(got) != 0 {
		t.Errorf("empty: %v", err)
	}
}

// flaky fails every read overlapping [lo, hi) with a non-EOF error.
type flaky struct {
	Data   []byte
	lo, hi int64
}

var errDisk = errors.New("disk on fire")

func (f *flaky) ReadAt(p []byte, off int64) (int, error) {
	if off < f.hi && off+int64(len(p)) > f.lo {
		return 0, errDisk
	}
	return copy(p, f.Data[off:]), nil
}

func TestReadErrors(t *testing.T) {
	big := pattern(8<<20, 3) // forces DIFAT sectors
	for _, data := range [][]byte{
		func() []byte { d, _ := build(3, sampleTree(), false); return d }(),
		func() []byte {
			d, _ := build(3, storage("Root Entry", stream("a", big), stream("b", []byte("x"))), false)
			return d
		}(),
	} {
		// A non-EOF error is returned as it is, whichever sector it strikes.
		step := int64(512)
		if len(data) > 1<<20 {
			step = 512 * 997 // sample; the metadata sectors are listed below
		}
		var spots []int64
		for off := int64(0); off < int64(len(data)); off += step {
			spots = append(spots, off)
		}
		for k := int64(1); k <= 80 && len(data) > 1<<20; k++ {
			spots = append(spots, int64(len(data))-k*512)
		}
		for _, off := range spots {
			fl := &flaky{Data: data, lo: off, hi: off + 512}
			f, err := Open(fl, int64(len(data)))
			if err != nil {
				if !errors.Is(err, errDisk) {
					t.Fatalf("sector at %d: %v", off, err)
				}
				continue
			}
			fl.lo, fl.hi = 0, int64(len(data)) // the disk dies after Open
			for _, c := range f.Root().Children {
				if _, err := f.ReadAll(c, 16<<20); c.Size > 0 && !errors.Is(err, errDisk) {
					t.Fatalf("%s after Open: %v", c.Name, err)
				}
			}
		}
	}
}

func TestSeedFiles(t *testing.T) {
	// The fuzz seeds in testdata are valid files; keep them so.
	files, _ := filepath.Glob("testdata/*.cfb")
	if len(files) == 0 {
		t.Fatal("no seed files")
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f := open(t, b)
		if f.Lookup("Dir/Deep/leaf") == nil {
			t.Errorf("%s: seed lost its tree", p)
		}
	}
}

// TestWriteSeeds regenerates testdata/*.cfb: CFB_WRITE_SEEDS=1 go test -run WriteSeeds
func TestWriteSeeds(t *testing.T) {
	if os.Getenv("CFB_WRITE_SEEDS") == "" {
		t.Skip("set CFB_WRITE_SEEDS=1 to regenerate testdata/*.cfb")
	}
	for _, v := range []int{3, 4} {
		tree := storage("Root Entry",
			stream("small", pattern(63, 2)),
			stream("big", pattern(9000, 5)),
			storage("Dir", stream("Inner", pattern(100, 6)), storage("Deep", stream("leaf", []byte("hello")))))
		b, _ := build(v, tree, v == 4)
		if err := os.WriteFile(filepath.Join("testdata", map[int]string{3: "v3.cfb", 4: "v4.cfb"}[v]), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzOpen(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/*.cfb")
	for _, p := range seeds {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, err := Open(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		var walk func(e *Entry, depth int)
		walk = func(e *Entry, depth int) {
			for _, c := range e.Children {
				if c.IsDir() {
					walk(c, depth+1)
				} else if _, err := fl.ReadAll(c, 1<<20); err != nil && !errors.Is(err, ErrFormat) && !errors.Is(err, ErrLimit) {
					t.Fatalf("unexpected error %v", err)
				}
			}
		}
		walk(fl.Root(), 0)
	})
}

func TestUpperSurrogates(t *testing.T) {
	if upper("a\U0001F600b") != "A\U0001F600B" {
		t.Fatal(upper("a\U0001F600b"))
	}
	if upper(string(rune(0xD800))) != string(rune(0xFFFD)) && upper("x") != "X" {
		t.Fatal("upper")
	}
}
