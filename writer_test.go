package cfb

import (
	"bytes"
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
