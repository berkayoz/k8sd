package events

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// dmesgPrefixRe strips the leading "[...]" timestamp prefix that `dmesg -H`
// produces. Examples:
//
//	[Mon Jan 15 10:00:00 2024] message
//	[  +0.000000] message
var dmesgPrefixRe = regexp.MustCompile(`^\[[^\]]*\]\s*`)

func collectDmesg(dumpDir, nodeRef string) []Event {
	path := filepath.Join(dumpDir, "sys", "dmesg")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	mtime := info.ModTime().UTC().Format(time.RFC3339)

	var out []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		msg := dmesgPrefixRe.ReplaceAllString(line, "")
		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}
		out = append(out, Event{
			Timestamp:  mtime,
			Severity:   dmesgSeverity(msg),
			Message:    msg,
			Source:     "kernel",
			ResourceID: nodeRef,
			EventType:  TypeSystem,
		})
	}
	return out
}

func dmesgSeverity(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "out of memory"),
		strings.Contains(lower, "oom-kill"),
		strings.Contains(lower, "oom_reaper"),
		strings.Contains(lower, "kernel panic"),
		strings.Contains(lower, "bug:"),
		strings.Contains(lower, "general protection fault"):
		return SeverityError
	}
	return SeverityWarning
}
