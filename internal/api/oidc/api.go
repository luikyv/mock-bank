package oidc

import (
	"net/http"
	"strings"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
)

type Server struct {
	provider *provider.Provider
	host     string
}

func NewServer(host string, provider *provider.Provider) Server {
	return Server{host: host, provider: provider}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{s.host},
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodHead, http.MethodGet, http.MethodPost},
	})
	secureMiddleware := secure.New(secure.Options{
		STSSeconds:            31536000,
		STSIncludeSubdomains:  true,
		STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' $NONCE; style-src 'self' $NONCE",
	})
	autorizeMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authorize") {
				handler := corsMiddleware.Handler(next)
				handler = secureMiddleware.Handler(handler)
				handler.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	s.provider.RegisterRoutes(mux, autorizeMiddleware)
}
