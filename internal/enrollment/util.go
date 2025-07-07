package enrollment

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"github.com/google/uuid"
)

func URN(id uuid.UUID) string {
	return URNPrefix + id.String()
}

func IDFromScopes(scopes string) (string, bool) {
	for s := range strings.SplitSeq(scopes, " ") {
		if ScopeID.Matches(s) {
			return strings.TrimPrefix(s, "enrollment:"+URNPrefix), true
		}
	}
	return "", false
}

func generateChallenge() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
