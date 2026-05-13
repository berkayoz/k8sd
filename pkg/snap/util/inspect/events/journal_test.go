package events

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestCollectJournals(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	svcDir := filepath.Join(tmp, "k8s.kubelet")
	g.Expect(os.MkdirAll(svcDir, 0o755)).To(Succeed())

	body := `2024-01-15T10:00:00+0000 host snap.k8s.kubelet[1234]: I0115 10:00:00.000001    1234 kubelet.go:1] Starting kubelet
2024-01-15T10:00:05+0000 host snap.k8s.kubelet[1234]: W0115 10:00:05.000001    1234 reflector.go:9] watch closed
2024-01-15T10:00:10+0000 host snap.k8s.kubelet[1234]: E0115 10:00:10.000001    1234 manager.go:3] OOMKilled: container exceeded memory limit
not a journal line, should be skipped
2024-01-15T10:00:20+0000 host snap.k8s.kubelet[1234]: pod sync failed for default/foo
`
	g.Expect(os.WriteFile(filepath.Join(svcDir, "journal.log"), []byte(body), 0o644)).To(Succeed())

	out := collectJournals(tmp)
	g.Expect(out).To(HaveLen(4))

	for _, e := range out {
		g.Expect(e.Source).To(Equal("kubelet"))
		g.Expect(e.ResourceID).To(Equal("service/kubelet"))
		g.Expect(e.EventType).To(Equal(TypeLog))
		g.Expect(e.Timestamp).ToNot(BeEmpty())
	}

	g.Expect(out[0].Timestamp).To(Equal("2024-01-15T10:00:00Z"))
	g.Expect(out[0].Severity).To(Equal(SeverityInfo))
	g.Expect(out[0].Message).To(Equal("Starting kubelet"))

	g.Expect(out[1].Timestamp).To(Equal("2024-01-15T10:00:05Z"))
	g.Expect(out[1].Severity).To(Equal(SeverityWarning))
	g.Expect(out[1].Message).To(Equal("watch closed"))

	g.Expect(out[2].Timestamp).To(Equal("2024-01-15T10:00:10Z"))
	g.Expect(out[2].Severity).To(Equal(SeverityError))
	g.Expect(out[2].Message).To(ContainSubstring("OOMKilled"))

	// Last line has no klog prefix; severity inferred from keyword "failed".
	g.Expect(out[3].Timestamp).To(Equal("2024-01-15T10:00:20Z"))
	g.Expect(out[3].Severity).To(Equal(SeverityError))
	g.Expect(out[3].Message).To(Equal("pod sync failed for default/foo"))

	// Timestamps must be distinct per-line, not all the same.
	g.Expect(out[0].Timestamp).ToNot(Equal(out[1].Timestamp))
	g.Expect(out[1].Timestamp).ToNot(Equal(out[2].Timestamp))
	g.Expect(out[2].Timestamp).ToNot(Equal(out[3].Timestamp))
}

func TestCollectJournalsHandlesNonUTCOffset(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	svcDir := filepath.Join(tmp, "k8s.kube-apiserver")
	g.Expect(os.MkdirAll(svcDir, 0o755)).To(Succeed())

	body := `2024-01-15T12:00:00+0200 host snap.k8s.kube-apiserver[1]: hello
`
	g.Expect(os.WriteFile(filepath.Join(svcDir, "journal.log"), []byte(body), 0o644)).To(Succeed())

	out := collectJournals(tmp)
	g.Expect(out).To(HaveLen(1))
	// 12:00+0200 == 10:00Z
	g.Expect(out[0].Timestamp).To(Equal("2024-01-15T10:00:00Z"))
	g.Expect(out[0].Source).To(Equal("kube-apiserver"))
}

// TestCollectJournalsShortIsoPrecise covers the `journalctl -o short-iso-precise`
// output that inspect actually requests: each line carries a microsecond
// fraction, so log bursts within a single wall-clock second still produce
// distinct timestamps in events.json.
func TestCollectJournalsShortIsoPrecise(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	svcDir := filepath.Join(tmp, "k8s.kubelet")
	g.Expect(os.MkdirAll(svcDir, 0o755)).To(Succeed())

	body := `2024-01-15T10:00:00.000123+0000 host snap.k8s.kubelet[1234]: first
2024-01-15T10:00:00.000456+0000 host snap.k8s.kubelet[1234]: second
2024-01-15T10:00:00.999999+0000 host snap.k8s.kubelet[1234]: third
`
	g.Expect(os.WriteFile(filepath.Join(svcDir, "journal.log"), []byte(body), 0o644)).To(Succeed())

	out := collectJournals(tmp)
	g.Expect(out).To(HaveLen(3))

	// All three lines fall in the same wall-clock second; with microsecond
	// precision they must remain distinct.
	g.Expect(out[0].Timestamp).ToNot(Equal(out[1].Timestamp))
	g.Expect(out[1].Timestamp).ToNot(Equal(out[2].Timestamp))
	g.Expect(out[0].Timestamp).To(Equal("2024-01-15T10:00:00.000123Z"))
	g.Expect(out[1].Timestamp).To(Equal("2024-01-15T10:00:00.000456Z"))
	g.Expect(out[2].Timestamp).To(Equal("2024-01-15T10:00:00.999999Z"))
}

func TestCollectJournalsIgnoresNonServiceDirs(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	g.Expect(os.MkdirAll(filepath.Join(tmp, "cluster-info"), 0o755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(tmp, "cluster-info", "journal.log"), []byte("2024-01-15T10:00:00+0000 host foo[1]: hi\n"), 0o644)).To(Succeed())

	g.Expect(collectJournals(tmp)).To(BeEmpty())
}
