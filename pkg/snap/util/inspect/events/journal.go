package events

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// journalLineRe matches `journalctl --utc -o short-iso[-precise]` output:
//
//	2024-01-15T10:00:00+0000           hostname svc[1234]: <message>  (short-iso)
//	2024-01-15T10:00:00.123456+0000    hostname svc[1234]: <message>  (short-iso-precise)
//
// The fractional-seconds segment is optional so the parser keeps working if
// the inspect command is ever reverted to short-iso, or if a journal mixes
// formats.
var journalLineRe = regexp.MustCompile(`^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\s+\S+\s+\S+:\s+(?P<msg>.*)$`)

// klogPrefixRe matches a klog-style severity prefix at the start of a message:
//
//	I0115 10:00:00.123456    1234 kubelet.go:123] <text>
var klogPrefixRe = regexp.MustCompile(`^([IWEF])\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\S+:\d+\]\s*`)

const (
	journalTimeLayout        = "2006-01-02T15:04:05-0700"
	journalTimeLayoutPrecise = "2006-01-02T15:04:05.999999-0700"
)

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

		ts := parseJournalTimestamp(tsRaw)
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

func parseJournalTimestamp(raw string) string {
	if t, err := time.Parse(journalTimeLayoutPrecise, raw); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(journalTimeLayout, raw); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return raw
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
