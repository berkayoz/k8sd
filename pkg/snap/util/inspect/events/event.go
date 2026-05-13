// Package events normalizes raw diagnostic files written by the inspect
// collector into a flat []Event slice conforming to the persephone pipeline's
// entry schema (persephone/models/schemas.py: Event).
package events

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"

	TypeLog      = "log_event"
	TypeMetric   = "metric_event"
	TypeSystem   = "system_event"
	TypeSnapshot = "process_snapshot_event"
)

// Event mirrors persephone/models/schemas.py:Event. JSON tags must match the
// Pydantic field names exactly so persephone can deserialize without remapping.
type Event struct {
	Timestamp  string `json:"timestamp"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Source     string `json:"source"`
	ResourceID string `json:"resource_id"`
	EventType  string `json:"event_type"`
}

// Collect walks the populated dumpDir and produces a chronologically sorted
// []Event from every supported source. Per-parser failures are non-fatal: the
// parser returns whatever it could extract and Collect continues.
func Collect(dumpDir, hostname string) []Event {
	if hostname == "" {
		hostname = "unknown"
	}
	nodeRef := "node/" + hostname

	var out []Event
	out = append(out, collectKubectlEvents(dumpDir)...)
	out = append(out, collectJournals(dumpDir)...)
	out = append(out, collectDmesg(dumpDir, nodeRef)...)
	out = append(out, collectSnapshots(dumpDir, nodeRef)...)

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp < out[j].Timestamp
	})
	return out
}

// Write encodes events as a JSON array to path.
func Write(path string, events []Event) error {
	if events == nil {
		events = []Event{}
	}
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write events.json: %w", err)
	}
	return nil
}
