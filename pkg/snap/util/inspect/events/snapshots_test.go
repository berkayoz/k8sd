package events

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

