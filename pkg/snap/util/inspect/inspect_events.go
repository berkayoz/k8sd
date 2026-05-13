package inspect

import (
	"os"
	"path/filepath"

	"github.com/canonical/k8sd/pkg/snap/util/inspect/events"
)

// writeStructuredEvents normalizes the populated dumpDir into a flat
// []events.Event and writes it as events.json next to the raw diagnostic files.
// The file is included in the tarball automatically.
//
// Errors are returned to the caller, which logs them as warnings — a failure
// here must not abort the inspection, since the raw tarball is still valuable.
func (c *collector) writeStructuredEvents() error {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	evs := events.Collect(c.dumpDir, hostname)
	return events.Write(filepath.Join(c.dumpDir, "events.json"), evs)
}
