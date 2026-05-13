package events

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestCollectSnapshots(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	sysDir := filepath.Join(tmp, "sys")
	g.Expect(os.MkdirAll(sysDir, 0o755)).To(Succeed())

	g.Expect(os.WriteFile(filepath.Join(sysDir, "ps"), []byte("UID PID PPID CMD\nroot 1 0 systemd\nroot 2 0 kthreadd\n"), 0o644)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(sysDir, "disk_usage"), []byte("Filesystem Size Used Avail Use%\n/dev/sda1 50G 10G 40G 20%\n"), 0o644)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(sysDir, "uptime"), []byte("10:00:00 up 1 day\n"), 0o644)).To(Succeed())

	out := collectSnapshots(tmp, "node/h1")

	byType := map[string]Event{}
	for _, e := range out {
		// Index by snapshot file label embedded in the message header.
		switch {
		case strings.Contains(e.Message, "ps -ef"):
			byType["ps"] = e
		case strings.Contains(e.Message, "df -h"):
			byType["df"] = e
		case strings.Contains(e.Message, "uptime"):
			byType["uptime"] = e
		}
	}

	g.Expect(byType["ps"].EventType).To(Equal(TypeSnapshot))
	g.Expect(byType["ps"].Message).To(ContainSubstring("3 lines"))

	g.Expect(byType["df"].EventType).To(Equal(TypeMetric))
	g.Expect(byType["df"].Message).To(ContainSubstring("2 lines"))

	g.Expect(byType["uptime"].EventType).To(Equal(TypeMetric))
	g.Expect(byType["uptime"].Message).To(ContainSubstring("1 lines"))

	// Files we didn't write (memory_usage, swap, lsmod) shouldn't produce events.
	g.Expect(out).To(HaveLen(3))

	for _, e := range out {
		g.Expect(e.Source).To(Equal("node"))
		g.Expect(e.ResourceID).To(Equal("node/h1"))
		g.Expect(e.Severity).To(Equal(SeverityInfo))
	}
}

// TestCollectSnapshotsDistinctTimestamps pins the requirement that snapshot
// events must not all share one timestamp, even when every snapshot file has
// the exact same mtime (which is the common case in production — the inspect
// runner writes them in a tight sequence within a single wall-clock second).
func TestCollectSnapshotsDistinctTimestamps(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	sysDir := filepath.Join(tmp, "sys")
	g.Expect(os.MkdirAll(sysDir, 0o755)).To(Succeed())

	// Write every snapshot file the collector knows about and force their
	// mtimes to the exact same instant — this is the worst-case scenario that
	// previously produced six events with identical timestamps.
	fixed := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	for _, spec := range snapshotSpecs {
		path := filepath.Join(sysDir, spec.file)
		g.Expect(os.WriteFile(path, []byte("header\nbody\n"), 0o644)).To(Succeed())
		g.Expect(os.Chtimes(path, fixed, fixed)).To(Succeed())
	}

	out := collectSnapshots(tmp, "node/h1")
	g.Expect(out).To(HaveLen(len(snapshotSpecs)))

	seen := map[string]bool{}
	for _, e := range out {
		g.Expect(seen).ToNot(HaveKey(e.Timestamp), "duplicate snapshot timestamp %q", e.Timestamp)
		seen[e.Timestamp] = true
	}
}

