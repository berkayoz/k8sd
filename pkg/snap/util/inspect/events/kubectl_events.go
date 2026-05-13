package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type k8sEventList struct {
	Items []k8sEvent `json:"items"`
}

type k8sEvent struct {
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"involvedObject"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Type           string `json:"type"`
	FirstTimestamp string `json:"firstTimestamp"`
	LastTimestamp  string `json:"lastTimestamp"`
	EventTime      string `json:"eventTime"`
}

// collectKubectlEvents walks the cluster-info dump directory and parses every
// events.json file that kubectl emits (one per namespace, plus optionally a
// top-level one).
func collectKubectlEvents(dumpDir string) []Event {
	clusterInfoDir := filepath.Join(dumpDir, "cluster-info")
	if _, err := os.Stat(clusterInfoDir); err != nil {
		return nil
	}

	var out []Event
	filepath.Walk(clusterInfoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Base(path) != "events.json" {
			return nil
		}
		out = append(out, parseEventsFile(path)...)
		return nil
	})
	return out
}

func parseEventsFile(path string) []Event {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var list k8sEventList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil
	}

	out := make([]Event, 0, len(list.Items))
	for _, e := range list.Items {
		out = append(out, eventFromK8s(e))
	}
	return out
}

func eventFromK8s(e k8sEvent) Event {
	ts := e.LastTimestamp
	if ts == "" {
		ts = e.FirstTimestamp
	}
	if ts == "" {
		ts = e.EventTime
	}

	severity := SeverityInfo
	if strings.EqualFold(e.Type, "Warning") {
		severity = SeverityWarning
	}

	resourceID := strings.ToLower(e.InvolvedObject.Kind) + "/" + e.InvolvedObject.Name
	if e.InvolvedObject.Namespace != "" {
		resourceID = e.InvolvedObject.Namespace + "/" + resourceID
	}

	msg := e.Message
	if e.Reason != "" {
		msg = e.Reason + ": " + msg
	}

	return Event{
		Timestamp:  ts,
		Severity:   severity,
		Message:    strings.TrimSpace(msg),
		Source:     e.InvolvedObject.Name,
		ResourceID: resourceID,
		EventType:  TypeLog,
	}
}
