package events

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestCollectDmesg(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	sysDir := filepath.Join(tmp, "sys")
	g.Expect(os.MkdirAll(sysDir, 0o755)).To(Succeed())

	body := `2024-01-15T10:00:00,000001+0000 usb 1-1: new high-speed USB device
2024-01-15T10:01:00,000002+0000 Out of memory: Killed process 1234 (api-server)
2024-01-15T10:02:00,000003+0000 BUG: kernel NULL pointer dereference
no timestamp on this line still emitted as fallback
`
	g.Expect(os.WriteFile(filepath.Join(sysDir, "dmesg"), []byte(body), 0o644)).To(Succeed())

	out := collectDmesg(tmp, "node/test-host")
	g.Expect(out).To(HaveLen(4))

	for _, e := range out {
		g.Expect(e.Source).To(Equal("kernel"))
		g.Expect(e.ResourceID).To(Equal("node/test-host"))
		g.Expect(e.EventType).To(Equal(TypeSystem))
		g.Expect(e.Timestamp).ToNot(BeEmpty())
	}

	g.Expect(out[0].Timestamp).To(Equal("2024-01-15T10:00:00Z"))
	g.Expect(out[0].Severity).To(Equal(SeverityWarning))
	g.Expect(out[0].Message).To(ContainSubstring("USB device"))

	g.Expect(out[1].Timestamp).To(Equal("2024-01-15T10:01:00Z"))
	g.Expect(out[1].Severity).To(Equal(SeverityError))
	g.Expect(out[1].Message).To(ContainSubstring("Out of memory"))

	g.Expect(out[2].Timestamp).To(Equal("2024-01-15T10:02:00Z"))
	g.Expect(out[2].Severity).To(Equal(SeverityError))

	// Line with no parseable timestamp falls back to file mtime; events from
	// other lines must have their own distinct, line-specific timestamps.
	g.Expect(out[0].Timestamp).ToNot(Equal(out[1].Timestamp))
	g.Expect(out[1].Timestamp).ToNot(Equal(out[2].Timestamp))
}

func TestCollectDmesgMissing(t *testing.T) {
	g := NewWithT(t)
	g.Expect(collectDmesg(t.TempDir(), "node/x")).To(BeEmpty())
}

func TestParseDmesgLineHandlesTimezone(t *testing.T) {
	g := NewWithT(t)

	ts, msg := parseDmesgLine("2024-01-15T12:00:00,000000+0200 something", "fallback")
	g.Expect(ts).To(Equal("2024-01-15T10:00:00Z"))
	g.Expect(msg).To(Equal("something"))
}
