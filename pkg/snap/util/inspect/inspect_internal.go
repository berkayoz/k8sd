package inspect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/canonical/k8sd/pkg/utils"
)

func (c *collector) isServiceActive(service string) bool {
	cmd := exec.Command("systemctl", "status", "snap."+service)
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), "active (running)")
}

func (c *collector) collectArgs() {
	c.logInfo("Copy service args to the final report tarball")
	src := c.snap.ServiceArgumentsDir()
	dst := filepath.Join(c.dumpDir, "args")
	if err := copyDir(src, dst); err != nil {
		c.logWarning(fmt.Sprintf("Failed to copy service args: %v", err))
	}
}

func (c *collector) collectClusterInfo(ctx context.Context) {
	c.logInfo("Copy k8s cluster-info dump to the final report tarball")
	clusterInfoDir := filepath.Join(c.dumpDir, "cluster-info")
	os.MkdirAll(clusterInfoDir, 0o755)

	flags := []string{}
	if c.opts.AllNamespaces {
		flags = []string{"--all-namespaces"}
	}

	cmd := []string{filepath.Join(c.k8sBinDir, "kubectl"), "cluster-info", "dump"}
	cmd = append(cmd, flags...)
	cmd = append(cmd, "--output-directory", clusterInfoDir)
	c.runWithTimeout(ctx, cmd, func(ec *exec.Cmd) { ec.Stdout = nil; ec.Stderr = nil })

	cmd = []string{filepath.Join(c.k8sBinDir, "kubectl"), "get", "upgrades", "-ojson"}
	cmd = append(cmd, flags...)
	outputFile := filepath.Join(clusterInfoDir, "upgrades.json")
	c.runWithTimeout(ctx, cmd, func(ec *exec.Cmd) {
		f, err := os.Create(outputFile)
		if err != nil {
			return
		}
		ec.Stdout = f
		ec.Stderr = f
	})
}

func (c *collector) collectSBOM() {
	c.logInfo("Copy SBOM to the final report tarball")
	bomPath := filepath.Join(c.snapDir, "bom.json")
	dstPath := filepath.Join(c.dumpDir, "sbom.json")
	if exists, _ := utils.FileExists(bomPath); exists {
		utils.CopyFile(bomPath, dstPath)
	}
}

func (c *collector) collectSystemInfo(ctx context.Context) {
	c.logInfo("Collect system information")
	sysDir := filepath.Join(c.dumpDir, "sys")
	os.MkdirAll(sysDir, 0o755)

	runAndCapture := func(name string, command []string) {
		outputPath := filepath.Join(sysDir, name)
		c.runWithTimeout(ctx, command, func(ec *exec.Cmd) {
			f, err := os.Create(outputPath)
			if err != nil {
				return
			}
			ec.Stdout = f
			ec.Stderr = f
		})
	}

	runAndCapture("ps", []string{"ps", "-ef"})
	runAndCapture("disk_usage", []string{"df", "-h"})
	runAndCapture("memory_usage", []string{"free", "-m"})
	runAndCapture("swap", []string{"swapon"})
	runAndCapture("uptime", []string{"uptime"})
	runAndCapture("loaded_kernel_modules", []string{"lsmod"})
	// ISO timestamps make each line independently parseable by the events
	// normalizer. -H's relative/short formats lose absolute time.
	runAndCapture("dmesg", []string{"dmesg", "--time-format=iso"})

	copyIfExists("/proc/mounts", filepath.Join(sysDir, "proc-mounts"))
	copyIfExists("/etc/os-release", filepath.Join(sysDir, "etc-os-release"))
}

func (c *collector) collectK8sDiagnostics(ctx context.Context) {
	c.logInfo("Copy uname to the final report tarball")
	c.runWithTimeout(ctx, []string{"uname", "-a"}, func(ec *exec.Cmd) {
		f, err := os.Create(filepath.Join(c.dumpDir, "uname.log"))
		if err != nil {
			return
		}
		ec.Stdout = f
		ec.Stderr = f
	})

	c.logInfo("Copy snap diagnostics to the final report tarball")
	captureSnapCmd := func(name string, command []string) {
		outputPath := filepath.Join(c.dumpDir, name)
		c.runWithTimeout(ctx, command, func(ec *exec.Cmd) {
			f, err := os.Create(outputPath)
			if err != nil {
				return
			}
			ec.Stdout = f
			ec.Stderr = f
		})
	}

	captureSnapCmd("snap-version.log", []string{"snap", "version"})
	captureSnapCmd("snap-list-k8s.log", []string{"snap", "list", "k8s"})
	captureSnapCmd("snap-services-k8s.log", []string{"snap", "services", "k8s"})
	captureSnapCmd("snap-logs-k8s.log", []string{"snap", "logs", "k8s", "-n", fmt.Sprintf("%d", c.opts.NumSnapLogEntries)})

	c.logInfo("Copy k8s diagnostics to the final report tarball")
	k8sdDir := filepath.Join(c.dumpDir, "k8s.k8sd")
	os.MkdirAll(k8sdDir, 0o755)

	captureK8sCmd := func(name string, command []string) {
		outputPath := filepath.Join(c.dumpDir, name)
		c.runWithTimeout(ctx, command, func(ec *exec.Cmd) {
			f, err := os.Create(outputPath)
			if err != nil {
				return
			}
			ec.Stdout = f
			ec.Stderr = f
		})
	}

	kubectlBin := filepath.Join(c.k8sBinDir, "kubectl")
	captureK8sCmd("k8s-version.log", []string{kubectlBin, "version"})
	captureK8sCmd("k8s-status.log", []string{filepath.Join(c.k8sBinDir, "k8s"), "status"})
	captureK8sCmd("k8s-get.log", []string{filepath.Join(c.k8sBinDir, "k8s"), "get"})
	captureK8sCmd("k8s.k8sd/k8sd-configmap.log", []string{kubectlBin, "get", "cm", "k8sd-config", "-n", "kube-system", "-o", "yaml"})
	captureK8sCmd("k8s-configmaps.log", []string{kubectlBin, "get", "cm", "-n", "kube-system"})

	stateDir := filepath.Join(c.snapCommon, "var", "lib", "k8sd", "state", "database")
	copyIfExists(filepath.Join(stateDir, "cluster.yaml"), filepath.Join(k8sdDir, "k8sd-cluster.yaml"))
	copyIfExists(filepath.Join(stateDir, "info.yaml"), filepath.Join(k8sdDir, "k8sd-info.yaml"))

	c.runWithTimeout(ctx, []string{"ls", "-la", filepath.Join(c.snapCommon, "var", "lib", "k8sd")}, func(ec *exec.Cmd) {
		f, err := os.Create(filepath.Join(k8sdDir, "k8sd-files.log"))
		if err != nil {
			return
		}
		ec.Stdout = f
		ec.Stderr = f
	})
}

func (c *collector) collectServiceDiagnostics(ctx context.Context, service string) {
	serviceDir := filepath.Join(c.dumpDir, service)
	os.MkdirAll(serviceDir, 0o755)

	statusFile := filepath.Join(serviceDir, "systemctl.log")
	c.runWithTimeout(ctx, []string{"systemctl", "status", "snap." + service}, func(ec *exec.Cmd) {
		f, err := os.Create(statusFile)
		if err != nil {
			return
		}
		ec.Stdout = f
		ec.Stderr = f
	})

	output, err := exec.Command("systemctl", "show", "snap."+service, "-p", "NRestarts").Output()
	var nRestarts string
	if err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(output)), "=", 2)
		if len(parts) == 2 {
			nRestarts = parts[1]
		}
	}

	if nRestarts == "" {
		nRestarts = "0"
	}

	f, err := os.OpenFile(filepath.Join(c.dumpDir, "nrestarts.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		fmt.Fprintf(f, "%s -> %s\n", service, nRestarts)
		f.Close()
	}

	if nRestarts != "0" && nRestarts != "" {
		c.logWarning(fmt.Sprintf("Service %s has restarted %s times due to errors", service, nRestarts))
	}

	journalFile := filepath.Join(serviceDir, "journal.log")
	// --utc + short-iso-precise gives each line a microsecond-precision ISO-8601
	// timestamp. short-iso (second precision) collapses bursty log lines onto
	// the same timestamp in events.json, which breaks downstream ordering.
	c.runWithTimeout(ctx, []string{"journalctl", "--utc", "-o", "short-iso-precise", "-n", fmt.Sprintf("%d", c.opts.NumSnapLogEntries), "-u", "snap." + service}, func(ec *exec.Cmd) {
		f, err := os.Create(journalFile)
		if err != nil {
			return
		}
		ec.Stdout = f
		ec.Stderr = f
	})
}

func (c *collector) collectRegistryMirrorLogs(ctx context.Context) {
	output, err := exec.Command("systemctl", "list-unit-files", "--state=enabled").Output()
	if err != nil {
		return
	}

	var mirrorUnits []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "registry-") {
			mirrorUnits = append(mirrorUnits, fields[0])
		}
	}

	if len(mirrorUnits) == 0 {
		return
	}

	mirrorsDir := filepath.Join(c.dumpDir, "mirrors")
	os.MkdirAll(mirrorsDir, 0o755)

	for _, unit := range mirrorUnits {
		journalFile := filepath.Join(mirrorsDir, unit+".log")
		c.runWithTimeout(ctx, []string{"journalctl", "-n", "100000", "-u", unit}, func(ec *exec.Cmd) {
			f, err := os.Create(journalFile)
			if err != nil {
				return
			}
			ec.Stdout = f
			ec.Stderr = f
		})
	}
}

func (c *collector) collectCoreDumps() {
	coreDumpDir := c.opts.CoreDumpDir
	dumpsDstDir := filepath.Join(c.dumpDir, "core_dumps")
	os.MkdirAll(dumpsDstDir, 0o755)

	entries, err := os.ReadDir(coreDumpDir)
	if err != nil || len(entries) == 0 {
		c.logInfo("Core dump directory empty or missing, skipping...")
		return
	}

	c.logInfo(fmt.Sprintf("Collecting core dumps from %s", coreDumpDir))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		src := filepath.Join(coreDumpDir, entry.Name())
		dst := filepath.Join(dumpsDstDir, entry.Name())
		utils.CopyFile(src, dst)
	}
}

func (c *collector) collectNetworkDiagnostics(ctx context.Context) {
	c.logInfo("Copy network diagnostics to the final report tarball")

	captureNetCmd := func(name string, command []string) {
		outputPath := filepath.Join(c.dumpDir, name)
		c.runWithTimeout(ctx, command, func(ec *exec.Cmd) {
			f, err := os.Create(outputPath)
			if err != nil {
				return
			}
			ec.Stdout = f
			ec.Stderr = f
		})
	}

	captureNetCmd("ip-a.log", []string{"ip", "a"})
	captureNetCmd("ip-r.log", []string{"ip", "r"})
	captureNetCmd("iptables.log", []string{"iptables-save"})
	captureNetCmd("iptables-legacy.log", []string{"iptables-legacy-save"})
	captureNetCmd("ss-plnt.log", []string{"ss", "-plnt"})
	captureNetCmd("iptables6.log", []string{"ip6tables-save"})
	captureNetCmd("iptables6-legacy.log", []string{"ip6tables-legacy-save"})
	captureNetCmd("ss-plntu.log", []string{"ss", "-plntu"})

	proxyEnv := c.parseProxyEnvironment()
	if len(proxyEnv) > 0 {
		utils.WriteFile(filepath.Join(c.dumpDir, "proxy_in_etc_environment"), []byte(strings.Join(proxyEnv, "\n")), 0o644)
	}
}

func (c *collector) checkExpectedServices(ctx context.Context, services []string) {
	for _, service := range services {
		c.collectServiceDiagnostics(ctx, service)
		if !c.isServiceActive(service) {
			c.logInfo(fmt.Sprintf("Service %s is not running", service))
			c.logWarning(fmt.Sprintf("Service %s should be running on this node", service))
		} else {
			c.logInfo(fmt.Sprintf("Service %s is running", service))
		}
	}
}

func (c *collector) parseProxyEnvironment() []string {
	data, err := os.ReadFile("/etc/environment")
	if err != nil {
		return nil
	}

	var result []string
	re := regexp.MustCompile(`^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY)=`)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			result = append(result, line)
		}
	}
	return result
}

func (c *collector) scanForCertificates(dir string) []string {
	return ScanForCertificates(dir)
}

func ScanForCertificates(dir string) []string {
	var matches []string
	re := regexp.MustCompile(`(?i)BEGIN CERTIFICATE|PRIVATE KEY`)

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		reader := bufio.NewReader(f)
		buf := make([]byte, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 && re.Match(buf[:n]) {
				rel, _ := filepath.Rel(dir, path)
				matches = append(matches, rel)
				return nil
			}
			if err != nil {
				break
			}
		}
		return nil
	})

	return matches
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		dstPath := filepath.Join(dst, rel)

		if info.IsDir() {
			os.MkdirAll(dstPath, info.Mode())
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer in.Close()

		out, err := os.Create(dstPath)
		if err != nil {
			return nil
		}
		defer out.Close()

		io.Copy(out, in)
		os.Chmod(dstPath, 0o644)
		return nil
	})
}

func copyIfExists(src, dst string) {
	if exists, _ := utils.FileExists(src); exists {
		utils.CopyFile(src, dst)
	}
}
