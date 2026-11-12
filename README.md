# cfb

Pure-Go reader for Microsoft Compound File Binary (MS-CFB, "OLE2") files: the
container of `.doc`, `.xls`, `.ppt` and `.msg` files, `.msi` installers and
Prim'X `.zed` archives. It is a small file system inside a file, so it sits
next to the other file-system readers of `go-filesystems`.

```go
f, err := cfb.Open(r, size) // r is an io.ReaderAt
if err != nil {             // errors.Is(err, cfb.ErrFormat)
	log.Fatal(err)
}
for _, e := range f.Root().Children { // storages and streams, in tree order
	fmt.Println(e.Name, e.IsDir(), e.Size)
}
e := f.Lookup("Storage/Stream") // case-insensitive, as MS-CFB orders names
data, err := f.ReadAll(e, 1<<20) // ErrLimit above 1 MiB
s, err := f.Open(e)              // or an io.ReaderAt: s.ReadAt, s.Size
```

## What it reads

* version 3 (512-byte sectors) and version 4 (4096-byte sectors) files;
* the FAT, the DIFAT (the 109 header entries and the DIFAT sector chain), the
  mini FAT and the mini stream (streams under 4096 bytes);
* the directory: red-black sibling trees, walked iteratively, with names
  compared as MS-CFB orders them (upper-cased UTF-16 code point by code point),
  creation and modification times, CLSID and state bits;
* streams as an `io.ReaderAt`, reading contiguous sectors in one call.

Writing is out of scope.

## What it refuses (untrusted input)

Every chain is bounded by the number of sectors the file can hold, and a
sector met twice is a cycle:

* a FAT, DIFAT or mini FAT count above the sector count, a DIFAT chain that
  loops, a FAT sector number at or beyond the end;
* a directory chain that loops or ends before the root, a sibling or child
  pointer out of range or reached twice, a name length that is odd, zero or
  above 64 bytes, an unknown object type;
* a stream whose size needs more sectors than its chain has, or more than the
  file holds, and a mini stream shorter than its mini FAT chains say
  (`ErrFormat`, never a zero-filled tail);
* a stream larger than the limit you pass to `ReadAll` (`ErrLimit`).

A version 3 stream size keeps only its low 32 bits, as MS-CFB recommends,
because older writers left the high half uninitialised. No allocation is sized
from a header field before it is compared with the file size, and directory
children are indexed once, so looking up every entry of a big storage is
linear.

## Tests

100 % statement coverage, `-race`, s390x under QEMU, `govulncheck`, and a fuzz
target (`FuzzOpen`) whose corpus is committed in `testdata/`. The tests build
files with `cfbtest`, a test-only writer (v3, v4, DIFAT, mini streams,
fragmented chains); no file written by Word, LibreOffice or any Microsoft
tool is committed, and none was available to generate.

## References

[MS-CFB] Compound File Binary File Format (Microsoft Open Specifications): the
header, the directory entry, the red-black tree and the DIFAT sectors.

## Licence

BSD-3-Clause. The reader was written for
[go-fde/zed](https://github.com/go-fde/zed) and moved here unchanged.
