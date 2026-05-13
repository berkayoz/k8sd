package events

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// dmesgIsoLineRe matches the format produced by `dmesg --time-format=iso`:
//
//	YYYY-MM-DDTHH:MM:SS,uuuuuu±HHMM message
//
// The microsecond separator is a comma (locale-dependent), and the timezone is
// the standard ±HHMM offset.
var dmesgIsoLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}),\d+([+-]\d{4})\s+(.*)$`)

const dmesgTimeLayout = "2006-01-02T15:04:05-0700"

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
	fallback := info.ModTime().UTC().Format(time.RFC3339)

	var out []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ts, msg := parseDmesgLine(line, fallback)
		if msg == "" {
			continue
		}
		out = append(out, Event{
			Timestamp:  ts,
			Severity:   dmesgSeverity(msg),
			Message:    msg,
			Source:     "kernel",
			ResourceID: nodeRef,
			EventType:  TypeSystem,
		})
	}
	return out
}

// parseDmesgLine returns (timestamp, message). If the line lacks a parseable
// timestamp, fallback is used so the event still has a valid ISO string.
func parseDmesgLine(line, fallback string) (string, string) {
	m := dmesgIsoLineRe.FindStringSubmatch(line)
	if m == nil {
		return fallback, line
	}
	t, err := time.Parse(dmesgTimeLayout, m[1]+m[2])
	if err != nil {
		return fallback, strings.TrimSpace(m[3])
	}
	return t.UTC().Format(time.RFC3339), strings.TrimSpace(m[3])
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
