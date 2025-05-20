package app

import (
	"time"
)

const (
	cookieSessionId = "sessionId"
	cookieNonce     = "nonce"
	sessionValidity = 24 * time.Hour
	nonceValidity   = 15 * time.Minute
)
