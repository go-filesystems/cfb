package cfb

import "github.com/go-filesystems/cfb/cfbtest"

type (
	node   = cfbtest.Node
	layout = cfbtest.Layout
)

func stream(name string, data []byte) *node    { return cfbtest.Stream(name, data) }
func storage(name string, kids ...*node) *node { return cfbtest.Storage(name, kids...) }
func build(version int, root *node, gappy bool) ([]byte, layout) {
	return cfbtest.Build(version, root, gappy)
}
