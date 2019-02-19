package common

import (
	"time"
)

type WhitelistedIP struct {
	IP        string
	ExpiresAt time.Time
	CreatedBy string
}

func NewWhitelistedIP(ip string, expiresAt time.Time, createdBy string) *WhitelistedIP {
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour * 24)
	}
	return &WhitelistedIP{
		IP:        ip,
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
	}
}
