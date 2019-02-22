package common

import (
	"time"
)

type WhitelistedIP struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
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

func (ip *WhitelistedIP) IsExpired() bool {
	return ip.ExpiresAt.Before(time.Now())
}
