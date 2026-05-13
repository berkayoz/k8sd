package events

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestCollectKubectlEvents(t *testing.T) {
	g := NewWithT(t)

	tmp := t.TempDir()
	clusterInfo := filepath.Join(tmp, "cluster-info", "default")
	g.Expect(os.MkdirAll(clusterInfo, 0o755)).To(Succeed())

	body := `{
  "kind": "List",
  "apiVersion": "v1",
  "items": [
    {
      "involvedObject": {"kind": "Pod", "namespace": "default", "name": "api-server"},
      "reason": "Failed",
      "message": "Error: ImagePullBackOff",
      "type": "Warning",
      "firstTimestamp": "2024-01-15T10:00:00Z",
      "lastTimestamp": "2024-01-15T10:01:00Z"
    },
    {
      "involvedObject": {"kind": "Pod", "namespace": "default", "name": "worker"},
      "reason": "Started",
      "message": "container started",
      "type": "Normal",
      "firstTimestamp": "2024-01-15T09:59:00Z",
      "lastTimestamp": "2024-01-15T09:59:00Z"
    }
  ]
}`
	g.Expect(os.WriteFile(filepath.Join(clusterInfo, "events.json"), []byte(body), 0o644)).To(Succeed())

	out := collectKubectlEvents(tmp)
	g.Expect(out).To(HaveLen(2))

	var failed, started Event
	for _, e := range out {
		switch e.Source {
		case "api-server":
			failed = e
		case "worker":
			started = e
		}
	}

	g.Expect(failed.Severity).To(Equal(SeverityWarning))
	g.Expect(failed.EventType).To(Equal(TypeLog))
	g.Expect(failed.Message).To(ContainSubstring("Failed"))
	g.Expect(failed.Message).To(ContainSubstring("ImagePullBackOff"))
	g.Expect(failed.ResourceID).To(Equal("default/pod/api-server"))
	g.Expect(failed.Timestamp).To(Equal("2024-01-15T10:01:00Z"))

	g.Expect(started.Severity).To(Equal(SeverityInfo))
	g.Expect(started.Timestamp).To(Equal("2024-01-15T09:59:00Z"))
}

func TestCollectKubectlEventsMissingDir(t *testing.T) {
	g := NewWithT(t)
	out := collectKubectlEvents(t.TempDir())
	g.Expect(out).To(BeEmpty())
}
