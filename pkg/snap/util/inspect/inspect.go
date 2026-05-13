package inspect

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	apiv2 "github.com/canonical/k8s-snap-api/v2/api"
	"github.com/canonical/k8sd/pkg/snap"
	"github.com/canonical/k8sd/pkg/utils"
)

type InspectOpts struct {
	OutputFile        string
	AllNamespaces     bool
	NumSnapLogEntries int
	Timeout           time.Duration
	CoreDumpDir       string
}

type collector struct {
	snap       snap.Snap
	opts       InspectOpts
	dumpDir    string
	timeouts   []string
	stdout     io.Writer
	k8sBinDir  string
	snapDir    string
	snapCommon string
}

func Inspect(ctx context.Context, s snap.Snap, stdout io.Writer, opts InspectOpts) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	dumpDir := filepath.Join(cwd, "inspection-report")
	if err := os.RemoveAll(dumpDir); err != nil {
		return fmt.Errorf("failed to remove existing inspection report directory: %w", err)
	}
	if err := os.MkdirAll(dumpDir, 0o755); err != nil {
		return fmt.Errorf("failed to create inspection report directory: %w", err)
	}

	c := &collector{
		snap:       s,
		opts:       opts,
		dumpDir:    dumpDir,
		stdout:     stdout,
		k8sBinDir:  s.K8sBinDir(),
		snapDir:    s.K8sScriptsDir() + "/..",
		snapCommon: filepath.Dir(s.ServiceArgumentsDir()),
	}

	controlPlaneServices := []string{
		"k8s.containerd", "k8s.etcd", "k8s.kube-proxy", "k8s.k8sd",
		"k8s.kube-apiserver", "k8s.kube-controller-manager", "k8s.kube-scheduler", "k8s.kubelet",
	}
	workerServices := []string{
		"k8s.containerd", "k8s.k8s-apiserver-proxy", "k8s.kubelet", "k8s.k8sd", "k8s.kube-proxy",
	}

	fmt.Fprintln(stdout, "Collecting service information")

	nodeType, err := c.determineNodeType(ctx)
	if err != nil {
		fmt.Fprintf(stdout, "Warning: could not determine node type: %v\n", err)
		nodeType = "unknown"
	}

	switch nodeType {
	case "worker":
		fmt.Fprintln(stdout, "Running inspection on a worker node")
		utils.WriteFile(filepath.Join(dumpDir, "is-worker-node"), []byte("Inspection ran on a worker node."), 0o644)
		c.checkExpectedServices(ctx, workerServices)
	default:
		if nodeType == "control-plane" {
			fmt.Fprintln(stdout, "Running inspection on a control-plane node")
			utils.WriteFile(filepath.Join(dumpDir, "is-control-plane-node"), []byte("Inspection ran on a control plane node."), 0o644)
		} else {
			fmt.Fprintln(stdout, "Running inspection on a node that is not bootstrapped.")
			utils.WriteFile(filepath.Join(dumpDir, "is-not-bootstrapped-node"), []byte("Inspection ran on a node that is not bootstrapped."), 0o644)
		}
		c.checkExpectedServices(ctx, controlPlaneServices)
	}

	fmt.Fprintln(stdout, "Collecting registry mirror logs")
	c.collectRegistryMirrorLogs(ctx)

	fmt.Fprintln(stdout, "Collecting service arguments")
	c.collectArgs()

	fmt.Fprintln(stdout, "Collecting k8s cluster-info")
	c.collectClusterInfo(ctx)

	fmt.Fprintln(stdout, "Collecting SBOM")
	c.collectSBOM()

	fmt.Fprintln(stdout, "Collecting system information")
	c.collectSystemInfo(ctx)

	c.collectCoreDumps()

	fmt.Fprintln(stdout, "Collecting snap and related information")
	c.collectK8sDiagnostics(ctx)

	fmt.Fprintln(stdout, "Collecting networking information")
	c.collectNetworkDiagnostics(ctx)

	if len(c.timeouts) > 0 {
		fmt.Fprintf(stdout, "\033[33m WARNING: \033[0m %d commands timed out. See timeout_warnings.log for details.\n", len(c.timeouts))
		timeoutLog := strings.Join(c.timeouts, "\n") + "\n"
		utils.WriteFile(filepath.Join(dumpDir, "timeout_warnings.log"), []byte(timeoutLog), 0o644)
	}

	if matches := c.scanForCertificates(dumpDir); len(matches) > 0 {
		fmt.Fprintf(stdout, "\033[31m WARNING: \033[0m Unexpected private key or certificate found in the report:\n")
		fmt.Fprintf(stdout, "\033[31m WARNING: \033[0m Found in the following files: %s\n", strings.Join(matches, ","))
		fmt.Fprintf(stdout, "\033[31m WARNING: \033[0m Please remove the private key or certificate from the report before sharing.\n")
	}

	fmt.Fprintln(stdout, "Normalizing diagnostics into events.json")
	if err := c.writeStructuredEvents(); err != nil {
		c.logWarning(fmt.Sprintf("failed to write events.json: %v", err))
	}

	fmt.Fprintln(stdout, "Building the report tarball")
	outputFile := opts.OutputFile
	if outputFile == "" {
		now := time.Now().Format("20060102_150405")
		outputFile = filepath.Join(cwd, "inspection-report-"+now+".tar.gz")
	}
	if err := utils.CreateTarball(outputFile, cwd, "inspection-report", nil); err != nil {
		return fmt.Errorf("failed to create report tarball: %w", err)
	}
	fmt.Fprintf(stdout, "\033[32m SUCCESS: \033[0m Report tarball is at %s\n", outputFile)

	return nil
}

func (c *collector) determineNodeType(ctx context.Context) (string, error) {
	client, err := c.snap.K8sdClient("")
	if err != nil {
		return "unknown", fmt.Errorf("failed to create k8sd client: %w", err)
	}

	resp, initialized, err := client.NodeStatus(ctx)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get node status: %w", err)
	}
	if !initialized {
		return "not-bootstrapped", nil
	}

	if resp.NodeStatus.ClusterRole == apiv2.ClusterRoleWorker {
		return "worker", nil
	}
	if resp.NodeStatus.ClusterRole == apiv2.ClusterRoleControlPlane {
		return "control-plane", nil
	}

	return "unknown", nil
}

func (c *collector) runWithTimeout(ctx context.Context, command []string, opts ...func(*exec.Cmd)) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	var args []string
	if len(command) > 1 {
		args = command[1:]
	}
	cmd := exec.CommandContext(timeoutCtx, command[0], args...)

	for _, o := range opts {
		o(cmd)
	}

	err := cmd.Run()
	if timeoutCtx.Err() == context.DeadlineExceeded {
		c.timeouts = append(c.timeouts, strings.Join(command, " "))
		return nil
	}
	return err
}

func (c *collector) logInfo(msg string) {
	fmt.Fprintf(c.stdout, "\033[34m INFO: \033[0m %s\n", msg)
}

func (c *collector) logWarning(msg string) {
	fmt.Fprintf(c.stdout, "\033[33m WARNING: \033[0m %s\n", msg)
}
