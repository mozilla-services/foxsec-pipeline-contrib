package common

import (
	"fmt"
	"time"
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

type AlertMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
