package conn

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"encoding/hex"

	"github.com/davecgh/go-spew/spew"
	"github.com/scionproto/scion/pkg/snet"
)

// DumpRawPacket writes the slice ​data​ into a file inside ​dir​
// and returns the absolute path.  It is safe to call from multiple
// goroutines.
//
// The file name is:
//
//	<dir>/<YYYYMMDD_HHMMSS>_<seq>.pkt
//
// where <seq> is a monotonically-increasing counter that guarantees
// uniqueness even when several packets land in the same micro-second.
func DumpRawPacket(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %q: %w", dir, err)
	}

	seq := atomic.AddUint64(&dumpSeq, 1)
	ts := time.Now().Format("20060102_150405.000000") // micro-second stamp
	name := fmt.Sprintf("%s_%06d.pkt", ts, seq)
	path := filepath.Join(dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	fmt.Fprintf(f, "==== Raw packet dump ====\ncreated: %s\n\n", ts)
	fmt.Fprint(f, hex.Dump(data))

	return path, nil
}

var dumpSeq uint64

func DumpSnetPacket(dir string, pkt *snet.Packet) (string, error) {
	if pkt == nil {
		return "", fmt.Errorf("DumpSnetPacket: nil packet")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %q: %w", dir, err)
	}

	seq := atomic.AddUint64(&dumpSeq, 1)
	ts := time.Now().Format("20060102_150405.000000") // micro-second stamp
	name := fmt.Sprintf("%s_%06d.dec", ts, seq)
	path := filepath.Join(dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	// 1) Pretty struct dump ----------------------------------------------------
	cfg := spew.ConfigState{
		Indent:                "  ",
		SortKeys:              true,
		DisablePointerMethods: false,
		DisableMethods:        false,
		ContinueOnMethod:      true,
		SpewKeys:              true,
		MaxDepth:              0, // unlimited
	}
	fmt.Fprintf(f, "==== snet.Packet dump ====\ncreated: %s\n\n", ts)
	cfg.Fdump(f, pkt)

	// 2) Raw bytes -------------------------------------------------------------
	fmt.Fprintln(f, "\n---- raw frame ----")
	if len(pkt.Bytes) == 0 {
		fmt.Fprintln(f, "(pkt.Bytes empty)")
	} else {
		fmt.Fprint(f, hex.Dump(pkt.Bytes))
	}

	return path, nil
}
