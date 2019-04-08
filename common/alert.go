package common

import (
	"fmt"
	"time"
)

const (
	ALERT_NEW          = "NEW"
	ALERT_ACKNOWLEDGED = "ACKLNOWLEDGED"
	ALERT_ESCALATED    = "ESCALATED"
)

type Alert struct {
	Id        string      `json:"id"`
	Severity  string      `json:"severity"`
	Category  string      `json:"category"`
	Summary   string      `json:"summary"`
	Payload   string      `json:"payload"`
	Metadata  []AlertMeta `json:"metadata"`
	Timestamp time.Time   `json:"timestamp"`
}

func (a *Alert) PrettyPrint() string {
	return fmt.Sprintf(`
	Summary: %s
	Severity: %s
	Category: %s
	Timestamp: %s
	Payload: %s
	Metadata: %v
	Id: %s`,
		a.Summary, a.Severity, a.Category, a.Timestamp, a.Payload, a.Metadata, a.Id)
}

func (a *Alert) OlderThan(dur time.Duration) bool {
	return a.Timestamp.Add(dur).Before(time.Now())
}

func (a *Alert) IsStatus(s string) bool {
	for _, am := range a.Metadata {
		if am.Key == "status" {
			return am.Value == s
		}
	}
	return false
}

type AlertMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
