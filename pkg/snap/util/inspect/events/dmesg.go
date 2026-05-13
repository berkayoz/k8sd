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
//	YYYY-MM-DDTHH:MM:SS[,.]uuuuuu±HH[:]MM message
//
// The fractional-seconds separator is a comma on most systems but is a period
// in some locales. The timezone offset is normally ±HHMM, but newer util-linux
// builds (and some distros) emit ±HH:MM — both must parse, otherwise every line
// falls back to the file mtime and all kernel events collapse onto a single
// timestamp in events.json.
var dmesgIsoLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[,.]\d+[+-]\d{2}:?\d{2})\s+(.*)$`)

const (
	dmesgTimeLayout      = "2006-01-02T15:04:05,999999-0700"
	dmesgTimeLayoutColon = "2006-01-02T15:04:05,999999Z07:00"
)

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
	raw := strings.Replace(m[1], ".", ",", 1)
	msg := strings.TrimSpace(m[2])
	if t, err := time.Parse(dmesgTimeLayoutColon, raw); err == nil {
		return t.UTC().Format(time.RFC3339Nano), msg
	}
	if t, err := time.Parse(dmesgTimeLayout, raw); err == nil {
		return t.UTC().Format(time.RFC3339Nano), msg
	}
	return fallback, msg
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
