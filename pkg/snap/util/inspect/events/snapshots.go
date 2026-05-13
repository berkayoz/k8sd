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
//
// All six snapshot commands run within milliseconds of each other inside
// collectSystemInfo, so their file mtimes often collide at second-level
// precision. We add a deterministic per-spec microsecond offset on top of the
// mtime to guarantee distinct, sortable timestamps in events.json regardless
// of filesystem mtime resolution.
func collectSnapshots(dumpDir, nodeRef string) []Event {
	sysDir := filepath.Join(dumpDir, "sys")
	if _, err := os.Stat(sysDir); err != nil {
		return nil
	}

	var out []Event
	for i, spec := range snapshotSpecs {
		path := filepath.Join(sysDir, spec.file)
		ev, ok := snapshotEvent(path, spec, nodeRef, i)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func snapshotEvent(path string, spec snapshotSpec, nodeRef string, idx int) (Event, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return Event{}, false
	}

	lineCount, firstLine := summarizeFile(path)
	msg := spec.label + " snapshot: " + strconv.Itoa(lineCount) + " lines"
	if firstLine != "" {
		msg += "; header=" + firstLine
	}

	ts := info.ModTime().UTC().Add(time.Duration(idx) * time.Microsecond)

	return Event{
		Timestamp:  ts.Format(time.RFC3339Nano),
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

