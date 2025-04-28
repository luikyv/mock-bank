package api

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	// By default, the encoding/json package escapes special characters like &, <, and >
	// to prevent potential security issues (e.g., XSS when embedding JSON in HTML).
	// However, this behavior is unnecessary in our case since some JSON objects
	// contain URLs, and escaping these characters can cause issues.
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(data)
}
