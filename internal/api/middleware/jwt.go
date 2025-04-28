package middleware

// func JWTRequest(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		jwsBytes, err := io.ReadAll(r.Body)
// 		if err != nil {
// 			http.Error(w, "Failed to read request body", http.StatusBadRequest)
// 			return
// 		}
// 		defer r.Body.Close()

// 		jws := string(jwsBytes)
// 		parsedJWT, err := jwt.ParseSigned(jws, []jose.SignatureAlgorithm{goidc.PS256})
// 		if err != nil {
// 			http.Error(w, "Invalid JWT", http.StatusUnauthorized)
// 			return
// 		}

// 		// Decode into a generic map
// 		var claims map[string]interface{}
// 		if err := parsedJWT.Claims(publicKey.Key, &claims); err != nil {
// 			http.Error(w, "Invalid JWT signature", http.StatusUnauthorized)
// 			return
// 		}

// 		// Marshal claims to JSON and replace the body
// 		jsonBytes, err := json.Marshal(claims)
// 		if err != nil {
// 			http.Error(w, "Failed to convert claims to JSON", http.StatusInternalServerError)
// 			return
// 		}

// 		r.Body = io.NopCloser(bytes.NewReader(jsonBytes))
// 		r.ContentLength = int64(len(jsonBytes))
// 		r.Header.Set("Content-Type", "application/json")

// 		// Proceed to the next handler
// 		next.ServeHTTP(w, r)
// 	})
// }

// type responseRecorder struct {
// 	http.ResponseWriter
// 	body   *strings.Builder
// 	status int
// }

// func (rr *responseRecorder) WriteHeader(status int) {
// 	rr.status = status
// 	rr.ResponseWriter.WriteHeader(status)
// }

// func (rr *responseRecorder) Write(b []byte) (int, error) {
// 	rr.body.Write(b)
// 	return rr.ResponseWriter.Write(b)
// }

// func fetchJWKS(orgID string) (jose.JSONWebKeySet, error) {
// 	return jose.JSONWebKeySet{}, nil
// }
