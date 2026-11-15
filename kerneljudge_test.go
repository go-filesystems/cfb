package cfb

// Python's olefile (an independent reader) and libgsf's `gsf createole` (an
// independent writer) as the judge of this driver, in a Tart VM. CFB is not a
// kernel filesystem. Skipped unless FS_KERNEL_JUDGE=1;
// github.com/go-filesystems/kerneljudge's cmd/kerneljudge sets it and runs
// this as root in the VM:
//
//	kerneljudge run --driver <clone of this repository> [--extra-dir <dir of .zed files>]

import (
	"crypto/sha256"
	"os"
	"strings"
	"testing"

	kj "github.com/go-filesystems/kerneljudge"
)

// cfbName keeps a corpus name inside what a CFB entry name can be: at most 31
// UTF-16 code units, and none of / \ : !.
func cfbMap(e kj.Entry) (kj.Entry, bool) { return e, true }

func writeCorpus(version int) func(img string, es []kj.Entry) error {
	return func(img string, es []kj.Entry) error {
		w := NewWriter(WithVersion(version))
		for _, e := range es {
			p := strings.TrimPrefix(e.Path, "/")
			var err error
			if e.Kind == kj.Dir {
				err = w.AddStorage(p, Attrs{})
			} else {
				err = w.AddStream(p, e.Content(), Attrs{})
			}
			if err != nil {
				return err
			}
		}
		f, err := os.Create(img)
		if err != nil {
			return err
		}
		if _, err := w.WriteTo(f); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
}

// readTree describes every storage and stream of an image as this reader sees it.
func readTree(img string) ([]kj.Node, error) {
	fh, err := os.Open(img)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	f, err := Open(fh, fi.Size())
	if err != nil {
		return nil, err
	}
	var ns []kj.Node
	var walk func(prefix string, e *Entry) error
	walk = func(prefix string, e *Entry) error {
		for _, c := range e.Children {
			p := prefix + "/" + c.Name
			if c.IsDir() {
				ns = append(ns, kj.Node{Path: p, Kind: kj.Dir})
				if err := walk(p, c); err != nil {
					return err
				}
				continue
			}
			data, err := f.ReadAll(c, 1<<40)
			if err != nil {
				return err
			}
			ns = append(ns, kj.Node{Path: p, Kind: kj.File, Size: int64(len(data)), SHA256: sha256.Sum256(data)})
		}
		return nil
	}
	return ns, walk("", f.Root())
}

func external(name string, version int) kj.External {
	return kj.External{
		Name:  name,
		Write: writeCorpus(version),
		Read:  readTree,
		Map:   cfbMap,
		Natives: []kj.Native{
			{Name: "gsf-createole", Args: []string{"sh", "-c", "cd {src} && gsf createole {img} * >/dev/null"}},
		},
		ExtraSuffix: ".zed",
	}
}

func TestKernelJudge(t *testing.T)   { kj.RunExternal(t, external("cfb-v3", 3)) }
func TestKernelJudgeV4(t *testing.T) { kj.RunExternal(t, external("cfb-v4", 4)) }
