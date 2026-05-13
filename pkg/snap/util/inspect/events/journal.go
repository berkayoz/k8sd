package events

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// journalLineRe matches the standard journalctl prefix:
//
//	Jan 15 10:00:00 hostname snap.k8s.kubelet[1234]: <message>
var journalLineRe = regexp.MustCompile(`^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(?P<msg>.*)$`)

// klogPrefixRe matches a klog-style severity prefix at the start of a message:
//
//	I0115 10:00:00.123456    1234 kubelet.go:123] <text>
var klogPrefixRe = regexp.MustCompile(`^([IWEF])\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\S+:\d+\]\s*`)

// collectJournals scans dumpDir for <service>/journal.log files written by
// collectServiceDiagnostics. Service directory names start with "k8s." which
// distinguishes them from cluster-info and other subdirectories.
func collectJournals(dumpDir string) []Event {
	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		return nil
	}

	var out []Event
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "k8s.") {
			continue
		}
		path := filepath.Join(dumpDir, entry.Name(), "journal.log")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		serviceShort := strings.TrimPrefix(entry.Name(), "k8s.")
		out = append(out, parseJournalFile(path, serviceShort)...)
	}
	return out
}

func parseJournalFile(path, service string) []Event {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	year := time.Now().Year()
	resourceID := "service/" + service

	var out []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		m := journalLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		tsRaw, msg := m[1], m[2]

		severity := severityFromMessage(msg)
		msg = klogPrefixRe.ReplaceAllString(msg, "")

		ts := parseJournalTimestamp(tsRaw, year)
		out = append(out, Event{
			Timestamp:  ts,
			Severity:   severity,
			Message:    strings.TrimSpace(msg),
			Source:     service,
			ResourceID: resourceID,
			EventType:  TypeLog,
		})
	}
	return out
}

func parseJournalTimestamp(raw string, year int) string {
	// "Jan 15 10:00:00" — assume current year, UTC. journalctl prints in local
	// time by default but the snap inspection environment is conventionally UTC;
	// we don't have timezone info in the prefix, so treating as UTC is the
	// safest no-info-loss choice.
	t, err := time.Parse("Jan 2 15:04:05", raw)
	if err != nil {
		return raw
	}
	t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	return t.Format(time.RFC3339)
}

func severityFromMessage(msg string) string {
	if m := klogPrefixRe.FindStringSubmatch(msg); m != nil {
		switch m[1] {
		case "E", "F":
			return SeverityError
		case "W":
			return SeverityWarning
		case "I":
			return SeverityInfo
		}
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "fatal"),
		strings.Contains(lower, "panic"),
		strings.Contains(lower, "error"),
		strings.Contains(lower, "failed"):
		return SeverityError
	case strings.Contains(lower, "warn"),
		strings.Contains(lower, "deprecated"):
		return SeverityWarning
	}
	return SeverityInfo
}
