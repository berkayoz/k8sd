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

	body := `[Mon Jan 15 10:00:00 2024] kernel: usb 1-1: new high-speed USB device
[Mon Jan 15 10:01:00 2024] Out of memory: Killed process 1234 (api-server)
[Mon Jan 15 10:02:00 2024] BUG: kernel NULL pointer dereference

`
	g.Expect(os.WriteFile(filepath.Join(sysDir, "dmesg"), []byte(body), 0o644)).To(Succeed())

	out := collectDmesg(tmp, "node/test-host")
	g.Expect(out).To(HaveLen(3))

	for _, e := range out {
		g.Expect(e.Source).To(Equal("kernel"))
		g.Expect(e.ResourceID).To(Equal("node/test-host"))
		g.Expect(e.EventType).To(Equal(TypeSystem))
	}

	g.Expect(out[0].Severity).To(Equal(SeverityWarning))
	g.Expect(out[0].Message).To(ContainSubstring("USB device"))

	g.Expect(out[1].Severity).To(Equal(SeverityError))
	g.Expect(out[1].Message).To(ContainSubstring("Out of memory"))

	g.Expect(out[2].Severity).To(Equal(SeverityError))
	g.Expect(out[2].Message).To(ContainSubstring("BUG"))
}

func TestCollectDmesgMissing(t *testing.T) {
	g := NewWithT(t)
	g.Expect(collectDmesg(t.TempDir(), "node/x")).To(BeEmpty())
}
