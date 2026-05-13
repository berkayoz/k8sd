package inspect_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiv2 "github.com/canonical/k8s-snap-api/v2/api"
	k8sdmock "github.com/canonical/k8sd/pkg/client/k8sd/mock"
	"github.com/canonical/k8sd/pkg/snap/mock"
	"github.com/canonical/k8sd/pkg/snap/util/inspect"
	"github.com/canonical/k8sd/pkg/snap/util/inspect/events"
	. "github.com/onsi/gomega"
)

func TestInspectDefaults(t *testing.T) {
	g := NewWithT(t)

	opts := inspect.InspectOpts{}
	g.Expect(opts.NumSnapLogEntries).To(BeZero())
	g.Expect(opts.AllNamespaces).To(BeFalse())
	g.Expect(opts.Timeout).To(BeZero())
	g.Expect(opts.CoreDumpDir).To(BeEmpty())
	g.Expect(opts.OutputFile).To(BeEmpty())
}

func newSnapMock(tmpDir string, clusterRole apiv2.ClusterRole, initialized bool) *mock.Snap {
	return &mock.Snap{
		Mock: mock.Mock{
			K8sdClient: &k8sdmock.Mock{
				NodeStatusResponse: apiv2.NodeStatusResponse{
					NodeStatus: apiv2.NodeStatus{
						ClusterRole: clusterRole,
					},
				},
				NodeStatusInitialized: initialized,
			},
			K8sScriptsDir:       filepath.Join(tmpDir, "snap", "k8s", "scripts"),
			K8sBinDir:           filepath.Join(tmpDir, "snap", "k8s", "bin"),
			ServiceArgumentsDir: filepath.Join(tmpDir, "snap-common", "args"),
			LockFilesDir:        filepath.Join(tmpDir, "snap-common", "lock"),
		},
	}
}

func mkdirs(m *mock.Snap) {
	os.MkdirAll(m.Mock.K8sScriptsDir, 0o755)
	os.MkdirAll(m.Mock.K8sBinDir, 0o755)
	os.MkdirAll(m.Mock.ServiceArgumentsDir, 0o755)
	os.MkdirAll(m.Mock.LockFilesDir, 0o755)
}

func readTarballPaths(t *testing.T, tarballPath string) []string {
	g := NewWithT(t)

	f, err := os.Open(tarballPath)
	g.Expect(err).ToNot(HaveOccurred())
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	g.Expect(err).ToNot(HaveOccurred())
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	var paths []string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		g.Expect(err).ToNot(HaveOccurred())
		paths = append(paths, header.Name)
	}
	return paths
}

func TestInspectCreatesTarball(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	snapMock := newSnapMock(tmpDir, apiv2.ClusterRoleControlPlane, true)
	mkdirs(snapMock)

	outputFile := filepath.Join(tmpDir, "test-report.tar.gz")

	opts := inspect.InspectOpts{
		OutputFile:        outputFile,
		NumSnapLogEntries: 100,
		Timeout:           5 * time.Second,
		CoreDumpDir:       filepath.Join(tmpDir, "coredumps"),
	}

	err := inspect.Inspect(context.Background(), snapMock, io.Discard, opts)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(outputFile).To(BeAnExistingFile())

	paths := readTarballPaths(t, outputFile)
	g.Expect(paths).To(ContainElement(ContainSubstring("is-control-plane-node")))
}

func TestInspectWorkerNode(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	snapMock := newSnapMock(tmpDir, apiv2.ClusterRoleWorker, true)
	mkdirs(snapMock)

	outputFile := filepath.Join(tmpDir, "worker-report.tar.gz")

	opts := inspect.InspectOpts{
		OutputFile:        outputFile,
		NumSnapLogEntries: 100,
		Timeout:           5 * time.Second,
		CoreDumpDir:       filepath.Join(tmpDir, "coredumps"),
	}

	err := inspect.Inspect(context.Background(), snapMock, io.Discard, opts)
	g.Expect(err).ToNot(HaveOccurred())

	paths := readTarballPaths(t, outputFile)
	g.Expect(paths).To(ContainElement(ContainSubstring("is-worker-node")))
}

func TestInspectNotBootstrappedNode(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	snapMock := newSnapMock(tmpDir, apiv2.ClusterRoleUnknown, false)
	mkdirs(snapMock)

	outputFile := filepath.Join(tmpDir, "notbootstrapped-report.tar.gz")

	opts := inspect.InspectOpts{
		OutputFile:        outputFile,
		NumSnapLogEntries: 100,
		Timeout:           5 * time.Second,
		CoreDumpDir:       filepath.Join(tmpDir, "coredumps"),
	}

	err := inspect.Inspect(context.Background(), snapMock, io.Discard, opts)
	g.Expect(err).ToNot(HaveOccurred())

	paths := readTarballPaths(t, outputFile)
	g.Expect(paths).To(ContainElement(ContainSubstring("is-not-bootstrapped-node")))
}

func TestInspectCoreDumps(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	coreDumpDir := filepath.Join(tmpDir, "coredumps")
	os.MkdirAll(coreDumpDir, 0o755)

	err := os.WriteFile(filepath.Join(coreDumpDir, "core.1234"), []byte("core dump data"), 0o644)
	g.Expect(err).ToNot(HaveOccurred())

	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	snapMock := newSnapMock(tmpDir, apiv2.ClusterRoleControlPlane, true)
	mkdirs(snapMock)

	outputFile := filepath.Join(tmpDir, "coredump-report.tar.gz")

	var stdout strings.Builder
	opts := inspect.InspectOpts{
		OutputFile:        outputFile,
		NumSnapLogEntries: 100,
		Timeout:           5 * time.Second,
		CoreDumpDir:       coreDumpDir,
	}

	err = inspect.Inspect(context.Background(), snapMock, &stdout, opts)
	g.Expect(err).ToNot(HaveOccurred())

	output := stdout.String()
	g.Expect(output).To(ContainSubstring("Collecting core dumps"))
}

func readTarballFile(t *testing.T, tarballPath, target string) ([]byte, bool) {
	g := NewWithT(t)

	f, err := os.Open(tarballPath)
	g.Expect(err).ToNot(HaveOccurred())
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	g.Expect(err).ToNot(HaveOccurred())
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		g.Expect(err).ToNot(HaveOccurred())
		if strings.HasSuffix(header.Name, "/"+target) || header.Name == target {
			data, err := io.ReadAll(tarReader)
			g.Expect(err).ToNot(HaveOccurred())
			return data, true
		}
	}
	return nil, false
}

func TestInspectEmitsEventsJSON(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	oldCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldCwd)

	snapMock := newSnapMock(tmpDir, apiv2.ClusterRoleControlPlane, true)
	mkdirs(snapMock)

	outputFile := filepath.Join(tmpDir, "events-report.tar.gz")

	opts := inspect.InspectOpts{
		OutputFile:        outputFile,
		NumSnapLogEntries: 100,
		Timeout:           5 * time.Second,
		CoreDumpDir:       filepath.Join(tmpDir, "coredumps"),
	}

	err := inspect.Inspect(context.Background(), snapMock, io.Discard, opts)
	g.Expect(err).ToNot(HaveOccurred())

	data, ok := readTarballFile(t, outputFile, "events.json")
	g.Expect(ok).To(BeTrue(), "events.json missing from tarball")

	var evs []events.Event
	g.Expect(json.Unmarshal(data, &evs)).To(Succeed())

	validSeverity := map[string]bool{events.SeverityInfo: true, events.SeverityWarning: true, events.SeverityError: true}
	validType := map[string]bool{events.TypeLog: true, events.TypeMetric: true, events.TypeSystem: true, events.TypeSnapshot: true}
	for _, e := range evs {
		g.Expect(validSeverity).To(HaveKey(e.Severity), "unexpected severity %q in %+v", e.Severity, e)
		g.Expect(validType).To(HaveKey(e.EventType), "unexpected event_type %q in %+v", e.EventType, e)
		g.Expect(e.Timestamp).ToNot(BeEmpty())
		g.Expect(e.ResourceID).ToNot(BeEmpty())
	}
}

func TestScanForCertificates(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	reportDir := filepath.Join(tmpDir, "inspection-report")
	os.MkdirAll(reportDir, 0o755)

	err := os.WriteFile(filepath.Join(reportDir, "cert.pem"), []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"), 0o644)
	g.Expect(err).ToNot(HaveOccurred())

	err = os.WriteFile(filepath.Join(reportDir, "safe.txt"), []byte("nothing sensitive here"), 0o644)
	g.Expect(err).ToNot(HaveOccurred())

	err = os.WriteFile(filepath.Join(reportDir, "key.pem"), []byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"), 0o644)
	g.Expect(err).ToNot(HaveOccurred())

	matches := inspect.ScanForCertificates(reportDir)
	g.Expect(matches).To(ContainElement(ContainSubstring("cert.pem")))
	g.Expect(matches).To(ContainElement(ContainSubstring("key.pem")))
	g.Expect(matches).ToNot(ContainElement(ContainSubstring("safe.txt")))
}
