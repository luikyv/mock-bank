package oidc

import (
	"net/http"

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
	s.provider.RegisterRoutes(
		mux,
		cors.New(cors.Options{
			AllowedOrigins:   []string{s.host},
			AllowCredentials: true,
			AllowedMethods:   []string{http.MethodHead, http.MethodGet, http.MethodPost},
		}).Handler,
		secure.New(secure.Options{
			STSSeconds:            31536000,
			STSIncludeSubdomains:  true,
			STSPreload:            true,
			FrameDeny:             true,
			ContentTypeNosniff:    true,
			BrowserXssFilter:      true,
			ContentSecurityPolicy: "default-src 'self'; script-src 'self' $NONCE; style-src 'self' $NONCE",
		}).Handler,
	)
}
