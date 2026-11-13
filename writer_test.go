package cfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

type writeFailure struct{ after int }

var errSink = errors.New("sink full")

func (w *writeFailure) Write(p []byte) (int, error) {
	if w.after == 0 {
		return 0, errSink
	}
	w.after--
	return len(p), nil
}

func written(t testing.TB, w *Writer) []byte {
	t.Helper()
	var b bytes.Buffer
	n, err := w.WriteTo(&b)
	if err != nil || n != int64(b.Len()) {
		t.Fatalf("WriteTo: %d, %v", n, err)
	}
	return b.Bytes()
}

func rnd(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 5))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// What a Writer writes, Open reads back: every attribute, both versions, with
// and without gaps, around the mini stream cutoff, with a DIFAT.
func TestWriterRoundTrip(t *testing.T) {
	created := time.Date(2026, 11, 11, 15, 9, 17, 253777000, time.UTC)
	modified := created.Add(90 * time.Minute)
	type item struct {
		path string
		data []byte // nil: a storage
	}
	items := []item{
		{"\x05Meta", rnd(1836, 1)}, {"Store", nil}, {"Store/CONTENTS", rnd(244, 2)}, {"Store/Big", rnd(70_000, 3)},
		{"Empty", []byte{}}, {"edge4095", rnd(4095, 4)}, {"edge4096", rnd(4096, 5)}, {"Store/Deep", nil}, {"Store/Deep/leaf", []byte("hello")},
		{"mini64", rnd(64, 6)}, {"mini65", rnd(65, 7)}, {"é ✓", rnd(10, 8)},
	}
	for _, version := range []int{3, 4} {
		for _, gaps := range []bool{false, true} {
			opts := []WriterOption{WithVersion(version)}
			if gaps {
				opts = append(opts, WithFreeSectorGaps())
			}
			w := NewWriter(opts...)
			clsid := [16]byte{0xE0, 0x0F, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
			w.SetRoot(Attrs{CLSID: clsid, Created: created})
			for i, it := range items {
				a := Attrs{Created: created, Modified: modified, StateBits: uint32(i)}
				a.CLSID[0] = byte(i + 1)
				var err error
				if it.data == nil {
					err = w.AddStorage(it.path, a)
				} else {
					err = w.AddStream(it.path, it.data, a)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			f := open(t, written(t, w))
			if f.Version() != version || f.Root().CLSID != clsid || !f.Root().Created.Equal(created.Truncate(100)) || !f.Root().Modified.IsZero() {
				t.Fatalf("v%d root: %+v", version, f.Root())
			}
			for i, it := range items {
				e := f.Lookup(it.path)
				if e == nil {
					t.Fatalf("v%d: %s missing", version, it.path)
				}
				if e.IsDir() != (it.data == nil) || e.StateBits != uint32(i) || e.CLSID[0] != byte(i+1) ||
					!e.Created.Equal(created.Truncate(100)) || !e.Modified.Equal(modified.Truncate(100)) {
					t.Fatalf("v%d %s: %+v", version, it.path, e)
				}
				if it.data != nil {
					got, err := f.ReadAll(e, 1<<20)
					if err != nil || !bytes.Equal(got, it.data) {
						t.Fatalf("v%d gaps=%v %s: %d bytes, %v", version, gaps, it.path, len(got), err)
					}
				}
			}
		}
	}
}

// More than 109 FAT sectors need DIFAT sectors.
func TestWriterDIFAT(t *testing.T) {
	big := rnd(17<<20, 9)
	w := NewWriter(WithLimits(10, 32<<20))
	if err := w.AddStream("huge", big, Attrs{}); err != nil {
		t.Fatal(err)
	}
	f := open(t, written(t, w))
	got, err := f.ReadAll(f.Lookup("huge"), 32<<20)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("huge: %v", err)
	}
}

// checkRaw reads the bytes of a written file with its own few lines, not with
// Open, and asserts what MS-CFB 2.1 and 2.3 require of the allocation tables:
// FAT sectors are marked FATSECT, DIFAT sectors DIFSECT, every chain ends with
// ENDOFCHAIN, the DIFAT chain too, and every unused FAT, mini FAT and DIFAT
// slot is FREESECT (zero is a valid sector number).
func checkRaw(t *testing.T, data []byte, wantDIFAT int) {
	t.Helper()
	le := binary.LittleEndian
	ssize := 1 << le.Uint16(data[30:])
	per := ssize / 4
	nSec := len(data)/ssize - 1
	sector := func(id uint32) []byte {
		if int(id) >= nSec {
			t.Fatalf("sector %d beyond the file (%d sectors)", id, nSec)
		}
		return data[(int(id)+1)*ssize : (int(id)+2)*ssize]
	}
	nFAT, nDIFAT := int(le.Uint32(data[44:])), int(le.Uint32(data[72:]))
	if nDIFAT != wantDIFAT {
		t.Fatalf("%d DIFAT sectors, want %d", nDIFAT, wantDIFAT)
	}
	// The FAT sector numbers: the header's 109, then the DIFAT chain.
	var fatIDs []uint32
	for i := 0; i < difatInHeader; i++ {
		v := le.Uint32(data[76+4*i:])
		if (i < nFAT) == (v == freeSect) {
			t.Fatalf("header DIFAT[%d] = %#x with %d FAT sectors", i, v, nFAT)
		}
		if v != freeSect {
			fatIDs = append(fatIDs, v)
		}
	}
	next := le.Uint32(data[68:])
	var difIDs []uint32
	for i := 0; i < nDIFAT; i++ {
		difIDs = append(difIDs, next)
		sec := sector(next)
		for j := 0; j < per-1; j++ {
			if v := le.Uint32(sec[4*j:]); v != freeSect {
				fatIDs = append(fatIDs, v)
			}
		}
		next = le.Uint32(sec[4*(per-1):])
	}
	if next != endOfChain {
		t.Fatalf("the DIFAT chain ends with %#x, not ENDOFCHAIN", next)
	}
	if len(fatIDs) != nFAT {
		t.Fatalf("%d FAT sector numbers, header says %d", len(fatIDs), nFAT)
	}
	var fat []uint32
	for _, id := range fatIDs {
		sec := sector(id)
		for j := 0; j < per; j++ {
			fat = append(fat, le.Uint32(sec[4*j:]))
		}
	}
	for _, id := range fatIDs {
		if fat[id] != fatSect {
			t.Fatalf("FAT sector %d is marked %#x, not FATSECT", id, fat[id])
		}
	}
	for _, id := range difIDs {
		if fat[id] != difSect {
			t.Fatalf("DIFAT sector %d is marked %#x, not DIFSECT", id, fat[id])
		}
	}
	nf, nd := 0, 0
	for i, v := range fat {
		switch {
		case v == fatSect:
			nf++
		case v == difSect:
			nd++
		case i >= nSec && v != freeSect:
			t.Fatalf("FAT[%d] = %#x beyond the last sector, not FREESECT", i, v)
		}
	}
	if nf != nFAT || nd != nDIFAT {
		t.Fatalf("%d FATSECT and %d DIFSECT entries, want %d and %d", nf, nd, nFAT, nDIFAT)
	}
	// walk follows a chain, which must end with ENDOFCHAIN, and returns it.
	walk := func(what string, start uint32) [][]byte {
		var out [][]byte
		for id := start; id != endOfChain; id = fat[id] {
			if len(out) > nSec || int(id) >= nSec {
				t.Fatalf("%s: chain loops or leaves the file at %#x", what, id)
			}
			out = append(out, sector(id))
		}
		return out
	}
	dirSecs := walk("directory", le.Uint32(data[48:]))
	var dir []byte
	for _, s := range dirSecs {
		dir = append(dir, s...)
	}
	root := dir[:dirEntrySize]
	miniSize := le.Uint64(root[120:])
	var miniFAT []uint32
	nMini := int(le.Uint32(data[64:]))
	if nMini > 0 {
		secs := walk("mini FAT", le.Uint32(data[60:]))
		if len(secs) != nMini {
			t.Fatalf("mini FAT: %d sectors, header says %d", len(secs), nMini)
		}
		for _, s := range secs {
			for j := 0; j < per; j++ {
				miniFAT = append(miniFAT, le.Uint32(s[4*j:]))
			}
		}
	}
	usedMini := int((miniSize + miniSectorSize - 1) / miniSectorSize)
	for i, v := range miniFAT {
		if (i < usedMini) == (v == freeSect) {
			t.Fatalf("mini FAT[%d] = %#x with %d mini sectors in use", i, v, usedMini)
		}
	}
	if usedMini > 0 {
		walk("mini stream", le.Uint32(root[116:]))
	}
	for i := 1; i*dirEntrySize < len(dir); i++ {
		e := dir[i*dirEntrySize : (i+1)*dirEntrySize]
		if e[66] == 2 && le.Uint64(e[120:]) >= miniCutoff {
			walk("stream", le.Uint32(e[116:]))
		}
	}
}

func TestWriterRawStructure(t *testing.T) {
	for _, version := range []int{3, 4} {
		for _, gaps := range []bool{false, true} {
			for _, n := range []int{0, 1, 3, 70} { // 70 mini streams: the mini FAT spills over a sector in v3
				opts := []WriterOption{WithVersion(version)}
				if gaps {
					opts = append(opts, WithFreeSectorGaps())
				}
				w := NewWriter(opts...)
				for i := 0; i < n; i++ {
					if err := w.AddStream(strings.Repeat("s", 1)+string(rune('A'+i%26))+string(rune('a'+i/26)), rnd(100+i, uint64(i)), Attrs{}); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.AddStream("big", rnd(9000, 1), Attrs{}); err != nil {
					t.Fatal(err)
				}
				checkRaw(t, written(t, w), 0)
			}
		}
	}
	// 17 MiB: 272 FAT sectors, 163 beyond the header's 109, so 2 DIFAT sectors.
	w := NewWriter(WithLimits(10, 32<<20))
	if err := w.AddStream("huge", rnd(17<<20, 9), Attrs{}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddStream("mini", rnd(100, 9), Attrs{}); err != nil {
		t.Fatal(err)
	}
	checkRaw(t, written(t, w), 2)
}

func TestWriterRefusals(t *testing.T) {
	w := NewWriter()
	if err := w.AddStorage("dir", Attrs{}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddStream("file", []byte("x"), Attrs{}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 32)
	for name, run := range map[string]func() error{
		"empty name":                       func() error { return w.AddStream("dir/", []byte("x"), Attrs{}) },
		"empty path":                       func() error { return w.AddStorage("", Attrs{}) },
		"name of 32 units":                 func() error { return w.AddStorage(long, Attrs{}) },
		"name of 32 units (non-BMP pairs)": func() error { return w.AddStorage(strings.Repeat("\U0001F600", 16), Attrs{}) },
		"slash handled as path":            func() error { return w.AddStorage("missing/child", Attrs{}) },
		"backslash":                        func() error { return w.AddStorage(`a\b`, Attrs{}) },
		"colon":                            func() error { return w.AddStorage("a:b", Attrs{}) },
		"bang":                             func() error { return w.AddStorage("a!b", Attrs{}) },
		"NUL":                              func() error { return w.AddStorage("a\x00b", Attrs{}) },
		"duplicate":                        func() error { return w.AddStream("dir", nil, Attrs{}) },
		"duplicate, other case":            func() error { return w.AddStorage("DIR", Attrs{}) },
		"parent is a stream":               func() error { return w.AddStorage("file/child", Attrs{}) },
	} {
		if err := run(); !errors.Is(err, ErrArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 31 UTF-16 units are fine, and so is a surrogate pair inside them.
	if err := w.AddStorage(strings.Repeat("a", 31), Attrs{}); err != nil {
		t.Errorf("31 units: %v", err)
	}
	if err := w.AddStorage(strings.Repeat("\U0001F600", 15)+"x", Attrs{}); err != nil {
		t.Errorf("31 units with pairs: %v", err)
	}
	// Limits: entries and bytes.
	l := NewWriter(WithLimits(2, 10))
	if err := l.AddStream("a", make([]byte, 6), Attrs{}); err != nil {
		t.Fatal(err)
	}
	if err := l.AddStream("b", make([]byte, 5), Attrs{}); !errors.Is(err, ErrLimit) {
		t.Errorf("bytes: %v", err)
	}
	if err := l.AddStream("b", make([]byte, 4), Attrs{}); err != nil {
		t.Errorf("exactly at the byte limit: %v", err)
	}
	if err := l.AddStorage("c", Attrs{}); !errors.Is(err, ErrLimit) {
		t.Errorf("entries: %v", err)
	}
	// Version 3 never holds more than 2 GiB, whatever limit is asked for.
	if v3 := NewWriter(WithLimits(1, 1<<40)); v3.maxBytes != 1<<31 {
		t.Errorf("version 3 byte limit %d", v3.maxBytes)
	}
	if v4 := NewWriter(WithVersion(4), WithLimits(1, 1<<40)); v4.maxBytes != 1<<40 {
		t.Errorf("version 4 byte limit %d", v4.maxBytes)
	}
	if _, err := NewWriter(WithVersion(5)).WriteTo(&bytes.Buffer{}); !errors.Is(err, ErrArgument) {
		t.Errorf("version 5: %v", err)
	}
}

func TestWriterReportsWriteErrors(t *testing.T) {
	w := NewWriter()
	w.AddStream("s", rnd(5000, 1), Attrs{})
	for after := 0; after < 8; after++ {
		n, err := w.WriteTo(&writeFailure{after: after})
		if !errors.Is(err, errSink) {
			t.Fatalf("failure after %d writes: %d, %v", after, n, err)
		}
	}
	if _, err := w.WriteTo(&bytes.Buffer{}); err != nil {
		t.Fatal(err) // and the Writer can be written again
	}
}

func TestWriterTimes(t *testing.T) {
	for _, tm := range []time.Time{{}, time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if filetimeOf(tm) != 0 {
			t.Errorf("%v must be 'not recorded'", tm)
		}
	}
	if got := filetime(filetimeOf(time.Unix(1_700_000_000, 123_400))); got.UnixNano() != 1_700_000_000_000_123_400 {
		t.Errorf("round trip %v", got.UnixNano())
	}
}

// The directory order of siblings is the one MS-CFB defines, so Open finds
// everything and Children come back shortest name first.
func TestWriterSiblingOrder(t *testing.T) {
	w := NewWriter()
	for _, n := range []string{"bb", "a", "CC", "ab", "B", "zzz"} {
		if err := w.AddStream(n, []byte(n), Attrs{}); err != nil {
			t.Fatal(err)
		}
	}
	f := open(t, written(t, w))
	var got []string
	for _, c := range f.Root().Children {
		got = append(got, c.Name)
	}
	if strings.Join(got, ",") != "a,B,ab,bb,CC,zzz" && strings.Join(got, ",") != "a,B,ab,bb,CC,zzz" {
		t.Fatalf("order %v", got)
	}
}

// FuzzWriter feeds the Writer names, sizes and tree shapes taken from the input:
// whatever it accepts must come back from Open the same, and whatever it
// refuses must be an ErrArgument or ErrLimit.
func FuzzWriter(f *testing.F) {
	f.Add([]byte("\x00a\x05hello\x01dir\x00\x00dir/x\x03abc"), uint8(3))
	f.Add([]byte("\x00\x00\x00\x01a\x00\x00"), uint8(4))
	f.Fuzz(func(t *testing.T, in []byte, version uint8) {
		w := NewWriter(WithVersion(3+int(version%2)), WithLimits(50, 1<<16))
		type want struct {
			dir  bool
			data []byte
		}
		accepted := map[string]want{}
		for len(in) >= 3 {
			kind, nl, dl := in[0]%2, int(in[1])%40, int(in[2])*3
			in = in[3:]
			if nl > len(in) {
				nl = len(in)
			}
			name := string(in[:nl])
			in = in[nl:]
			path := name
			if len(accepted) > 0 && kind == 1 { // try under the first storage we know
				for p, v := range accepted {
					if v.dir {
						path = p + "/" + name
						break
					}
				}
			}
			var err error
			if kind == 0 {
				err = w.AddStorage(path, Attrs{})
				if err == nil {
					accepted[path] = want{dir: true}
				}
			} else {
				data := make([]byte, dl)
				for i := range data {
					data[i] = byte(i * 7)
				}
				err = w.AddStream(path, data, Attrs{})
				if err == nil {
					accepted[path] = want{data: data}
				}
			}
			if err != nil && !errors.Is(err, ErrArgument) && !errors.Is(err, ErrLimit) {
				t.Fatalf("unexpected error %v", err)
			}
		}
		var b bytes.Buffer
		if _, err := w.WriteTo(&b); err != nil {
			t.Fatal(err)
		}
		file, err := Open(bytes.NewReader(b.Bytes()), int64(b.Len()))
		if err != nil {
			t.Fatalf("the Writer's own output does not open: %v", err)
		}
		for path, v := range accepted {
			e := file.Lookup(path)
			if e == nil || e.IsDir() != v.dir {
				t.Fatalf("%q lost or changed kind", path)
			}
			if !v.dir {
				got, err := file.ReadAll(e, 1<<20)
				if err != nil || !bytes.Equal(got, v.data) {
					t.Fatalf("%q: %v", path, err)
				}
			}
		}
	})
}
