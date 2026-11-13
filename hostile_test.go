package cfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// miniPair is a file with two 64-byte mini streams, "a" in mini sector 0 and
// "b" in mini sector 1, and where its root directory entry is.
func miniPair() ([]byte, layout) {
	a, b := bytes.Repeat([]byte{0xAA}, 64), bytes.Repeat([]byte{0xBB}, 64)
	return build(3, storage("Root Entry", stream("a", a), stream("b", b)), false)
}

// A mini stream shorter than its mini FAT chains used to be zero-filled
// silently: the bytes past its end came back as 0x00.
func TestShortMiniStreamIsRefused(t *testing.T) {
	raw, lay := miniPair()
	binary.LittleEndian.PutUint64(raw[lay.DirOff+120:], 100) // root: mini stream cut to 100 bytes
	f := open(t, raw)
	if got, err := f.ReadAll(f.Lookup("a"), 1<<20); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 64)) {
		t.Fatalf("a lies inside the mini stream: %v", err)
	}
	got, err := f.ReadAll(f.Lookup("b"), 1<<20)
	if !errors.Is(err, ErrFormat) || got != nil {
		t.Fatalf("b runs past the mini stream: %d bytes, err %v", len(got), err)
	}
	// And through ReadAt, the way a streaming caller meets it.
	s, err := f.Open(f.Lookup("b"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReadAt(make([]byte, 64), 0); n == 64 || !errors.Is(err, ErrFormat) {
		t.Fatalf("ReadAt past the mini stream: %d, %v", n, err)
	}
}

// The mini FAT walk may use the sectors the mini stream holds, not one more.
func TestMiniWalkLimit(t *testing.T) {
	raw, lay := miniPair()
	binary.LittleEndian.PutUint64(raw[lay.DirOff+120:], 64) // one mini sector
	f := open(t, raw)
	if _, err := f.Open(f.Lookup("a")); err != nil {
		t.Fatalf("a is the one sector there is: %v", err)
	}
	if _, err := f.Open(f.Lookup("b")); !errors.Is(err, ErrFormat) { // at Open, not at the first read
		t.Fatalf("b is one sector past the mini stream: %v", err)
	}
}

// A FAT sector number equal to the sector count is out of range, even when the
// reader happens to hold bytes there (a reader larger than the declared size).
func TestFATSectorAtSectorCount(t *testing.T) {
	data, lay := build(3, storage("Root Entry", stream("s", []byte("x"))), false)
	nSectors := (len(data) - 1) / 512
	extra := append([]byte(nil), data[lay.FatOff:lay.FatOff+512]...)
	b := append(append([]byte(nil), data...), extra...)
	binary.LittleEndian.PutUint32(b[76:], uint32(nSectors))
	if _, err := Open(bytes.NewReader(b), int64(len(data))); !errors.Is(err, ErrFormat) {
		t.Fatalf("FAT sector %d of %d accepted: %v", nSectors, nSectors, err)
	}
	// Control: the same bytes with the true FAT sector open fine.
	if _, err := Open(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
}

// Hostile headers: cycles and absurd counts end in ErrFormat, quickly.
func TestHostileHeaders(t *testing.T) {
	le := binary.LittleEndian
	header := func(shift uint16, nFAT, nDIFAT, firstDIFAT uint32) []byte {
		h := make([]byte, 512)
		copy(h, signature[:])
		le.PutUint16(h[24:], 0x3E)
		le.PutUint16(h[26:], 3)
		le.PutUint16(h[28:], 0xFFFE)
		le.PutUint16(h[30:], shift)
		le.PutUint16(h[32:], 6)
		le.PutUint32(h[44:], nFAT)
		le.PutUint32(h[48:], 0)
		le.PutUint32(h[56:], 4096)
		le.PutUint32(h[60:], endOfChain)
		le.PutUint32(h[68:], firstDIFAT)
		le.PutUint32(h[72:], nDIFAT)
		for i := 0; i < 109; i++ {
			le.PutUint32(h[76+4*i:], freeSect)
		}
		return h
	}
	cases := map[string][]byte{}
	{ // a DIFAT sector whose next pointer is itself, as many times as sectors
		body := make([]byte, 200*512)
		for s := 0; s < 200; s++ {
			sec := body[s*512 : (s+1)*512]
			for i := 0; i < 127; i++ {
				le.PutUint32(sec[4*i:], freeSect)
			}
			le.PutUint32(sec[508:], 0)
		}
		cases["DIFAT cycle"] = append(header(9, 100, 200, 0), body...)
	}
	{ // the directory chain loops 0 -> 0
		f := header(9, 1, 0, endOfChain)
		le.PutUint32(f[76:], 0)
		cases["FAT self loop"] = append(f, make([]byte, 2*512)...)
	}
	cases["FAT sectors 2^32-1"] = header(9, 0xFFFFFFFF, 0, endOfChain)
	cases["version 3, shift 12"] = header(12, 0, 0, endOfChain)
	for name, b := range cases {
		start := time.Now()
		if _, err := Open(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s took %v", name, time.Since(start))
		}
	}
}

// Looking up every child of a big storage is linear, and safe for concurrent use.
func TestChildIndex(t *testing.T) {
	const n = 3000
	var kids []*node
	for i := 0; i < n; i++ {
		kids = append(kids, stream(fmt.Sprintf("Stream%05d", i), []byte{byte(i)}))
	}
	data, _ := build(3, storage("Root Entry", kids...), false)
	f := open(t, data)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				e := f.Lookup(fmt.Sprintf("STREAM%05d", i)) // case-insensitive
				if e == nil || e.Name != fmt.Sprintf("Stream%05d", i) {
					t.Errorf("stream %d not found", i)
					return
				}
			}
		}()
	}
	wg.Wait()
	// With a name twice (invalid), the first one in tree order answers.
	dup := &Entry{Children: []*Entry{{Name: "x", Size: 1}, {Name: "X", Size: 2}}}
	if dup.Child("x").Size != 1 {
		t.Fatal("duplicate names: first must win")
	}
}

// TestWriteFuzzSeeds regenerates testdata/fuzz/FuzzOpen (CFB_WRITE_SEEDS=1).
func TestWriteFuzzSeeds(t *testing.T) {
	if os.Getenv("CFB_WRITE_SEEDS") == "" {
		t.Skip("set CFB_WRITE_SEEDS=1 to regenerate testdata/fuzz")
	}
	shortMini, lay := miniPair()
	binary.LittleEndian.PutUint64(shortMini[lay.DirOff+120:], 100)
	small := storage("Root Entry", stream("s", pattern(63, 2)), stream("m", pattern(5000, 3)), storage("Dir", stream("leaf", []byte("hello"))))
	v3, _ := build(3, small, false)
	v4, _ := build(4, small, true)
	if err := os.MkdirAll("testdata/fuzz/FuzzOpen", 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"v3-tree": v3, "v4-gappy": v4, "short-mini": shortMini} {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%s)\n", strconv.Quote(string(data)))
		if err := os.WriteFile("testdata/fuzz/FuzzOpen/"+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A DIFAT chain that loops is refused even when the sectors it supplies are
// already enough: the walk used to stop after nDIFAT sectors and accept it.
func TestDIFATLoopWithEnoughFATIDs(t *testing.T) {
	le := binary.LittleEndian
	data, lay := build(3, storage("Root Entry", stream("s", []byte("x"))), false)
	fatID := uint32(lay.FatOff/512 - 1)
	first := uint32((len(data) - 1) / 512) // the sector appended below
	sec := make([]byte, 512)
	for i := 0; i < 127; i++ {
		le.PutUint32(sec[4*i:], freeSect)
	}
	le.PutUint32(sec[0:], fatID) // the one FAT sector, found through the DIFAT
	le.PutUint32(sec[508:], first)
	mk := func(nDIFAT uint32) []byte {
		b := append(append([]byte(nil), data...), sec...)
		for i := 0; i < difatInHeader; i++ {
			le.PutUint32(b[76+4*i:], freeSect) // nothing in the header's own DIFAT
		}
		le.PutUint32(b[68:], first)
		le.PutUint32(b[72:], nDIFAT)
		return b
	}
	// Control: one DIFAT sector, which is all there is, opens.
	b := mk(1)
	if _, err := Open(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatalf("one DIFAT sector: %v", err)
	}
	// The sector pointing at itself, declared twice: the second visit is a loop.
	b = mk(2)
	if _, err := Open(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrFormat) {
		t.Fatalf("a DIFAT loop that still supplies the FAT ids: %v", err)
	}
}
