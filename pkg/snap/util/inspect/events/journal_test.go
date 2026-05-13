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

	body := `Jan 15 10:00:00 host snap.k8s.kubelet[1234]: I0115 10:00:00.000001    1234 kubelet.go:1] Starting kubelet
Jan 15 10:00:05 host snap.k8s.kubelet[1234]: W0115 10:00:05.000001    1234 reflector.go:9] watch closed
Jan 15 10:00:10 host snap.k8s.kubelet[1234]: E0115 10:00:10.000001    1234 manager.go:3] OOMKilled: container exceeded memory limit
not a journal line, should be skipped
Jan 15 10:00:20 host snap.k8s.kubelet[1234]: pod sync failed for default/foo
`
	g.Expect(os.WriteFile(filepath.Join(svcDir, "journal.log"), []byte(body), 0o644)).To(Succeed())

	out := collectJournals(tmp)
	g.Expect(out).To(HaveLen(4))

	for _, e := range out {
		g.Expect(e.Source).To(Equal("kubelet"))
		g.Expect(e.ResourceID).To(Equal("service/kubelet"))
		g.Expect(e.EventType).To(Equal(TypeLog))
	}

	g.Expect(out[0].Severity).To(Equal(SeverityInfo))
	g.Expect(out[0].Message).To(Equal("Starting kubelet"))

	g.Expect(out[1].Severity).To(Equal(SeverityWarning))
	g.Expect(out[1].Message).To(Equal("watch closed"))

	g.Expect(out[2].Severity).To(Equal(SeverityError))
	g.Expect(out[2].Message).To(ContainSubstring("OOMKilled"))

	// Last line has no klog prefix; severity inferred from keyword "failed".
	g.Expect(out[3].Severity).To(Equal(SeverityError))
	g.Expect(out[3].Message).To(Equal("pod sync failed for default/foo"))
}

func TestCollectJournalsIgnoresNonServiceDirs(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	// cluster-info should not be picked up as a service.
	g.Expect(os.MkdirAll(filepath.Join(tmp, "cluster-info"), 0o755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(tmp, "cluster-info", "journal.log"), []byte("Jan 15 10:00:00 host foo[1]: hi\n"), 0o644)).To(Succeed())

	g.Expect(collectJournals(tmp)).To(BeEmpty())
}
