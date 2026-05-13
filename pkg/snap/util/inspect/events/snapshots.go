package events

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type snapshotSpec struct {
	file      string
	eventType string
	label     string
}

var snapshotSpecs = []snapshotSpec{
	{file: "ps", eventType: TypeSnapshot, label: "ps -ef"},
	{file: "disk_usage", eventType: TypeMetric, label: "df -h"},
	{file: "memory_usage", eventType: TypeMetric, label: "free -m"},
	{file: "swap", eventType: TypeMetric, label: "swapon"},
	{file: "uptime", eventType: TypeMetric, label: "uptime"},
	{file: "loaded_kernel_modules", eventType: TypeMetric, label: "lsmod"},
}

// collectSnapshots emits one Event per system snapshot file. The body of each
// file is not parsed line-by-line because these snapshots are point-in-time
// summaries; the line count and the first non-empty content line are enough
// signal for downstream RCA.
func collectSnapshots(dumpDir, nodeRef string) []Event {
	sysDir := filepath.Join(dumpDir, "sys")
	if _, err := os.Stat(sysDir); err != nil {
		return nil
	}

	var out []Event
	for _, spec := range snapshotSpecs {
		path := filepath.Join(sysDir, spec.file)
		ev, ok := snapshotEvent(path, spec, nodeRef)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func snapshotEvent(path string, spec snapshotSpec, nodeRef string) (Event, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return Event{}, false
	}

	lineCount, firstLine := summarizeFile(path)
	msg := spec.label + " snapshot: " + strconv.Itoa(lineCount) + " lines"
	if firstLine != "" {
		msg += "; header=" + firstLine
	}

	return Event{
		Timestamp:  info.ModTime().UTC().Format(time.RFC3339),
		Severity:   SeverityInfo,
		Message:    msg,
		Source:     "node",
		ResourceID: nodeRef,
		EventType:  spec.eventType,
	}, true
}

func summarizeFile(path string) (int, string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var count int
	var first string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		if first == "" {
			first = line
		}
	}
	return count, first
}

