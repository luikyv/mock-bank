package app

import (
	"time"
)

type ContextKey string

const (
	CtxKeyOrgID         ContextKey = "org_id"
	CtxKeySessionID     ContextKey = "session_id"
	CtxKeyInteractionID ContextKey = "interaction_id"
)

const (
	cookieSessionId = "sessionId"
	cookieNonce     = "nonce"
	sessionValidity = 24 * time.Hour
	nonceValidity   = 15 * time.Minute
)
