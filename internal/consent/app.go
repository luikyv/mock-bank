package consent

import (
	"net/http"

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/api/middleware"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
)

type AppServer struct {
	host    string
	service Service
}

func NewAppServer(host string, service Service) AppServer {
	return AppServer{
		host:    host,
		service: service,
	}
}

func (s AppServer) Register(mux *http.ServeMux) {
	consentMux := http.NewServeMux()

	handler := s.consentsHandler()
	handler = middleware.AppAuth(handler)
	consentMux.Handle("GET /app/consents", handler)

	handler = consentMux
	handler = middleware.Meta(handler, s.host)
	mux.Handle("/app/consents", handler)
}

func (s AppServer) consentsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		orgID := r.Context().Value(api.CtxKeyOrgID).(string)
		pag, err := api.NewPagination(r)
		if err != nil {
			writeAppError(w, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, err.Error()))
			return
		}

		cs, err := s.service.consents(r.Context(), userID, orgID, pag)
		if err != nil {
			writeAppError(w, err)
			return
		}

		resp := toConsentsAdminResponse(cs, s.host)
		api.WriteJSON(w, resp, http.StatusOK)
	})
}

type consentsAppResponse struct {
	Data  []consentAppResponse `json:"data"`
	Links api.Links            `json:"links"`
	Meta  api.Meta             `json:"meta"`
}

type consentAppResponse struct {
	ID                   string          `json:"consentId"`
	Status               Status          `json:"status"`
	Permissions          []Permission    `json:"permissions"`
	CreationDateTime     timex.DateTime  `json:"creationDateTime"`
	StatusUpdateDateTime timex.DateTime  `json:"statusUpdateDateTime"`
	ExpirationDateTime   *timex.DateTime `json:"expirationDateTime,omitempty"`
	RejectedBy           RejectedBy      `json:"rejectedBy,omitempty"`
	RejectionReason      RejectionReason `json:"rejectionReason,omitempty"`
	UserID               string          `json:"userId"`
	ClientID             string          `json:"clientId"`
}

func toConsentsAdminResponse(cs page.Page[Consent], reqURL string) consentsAppResponse {

	resp := consentsAppResponse{
		Data:  []consentAppResponse{},
		Meta:  api.NewPaginatedMeta(cs),
		Links: api.NewPaginatedLinks(reqURL, cs),
	}

	for _, c := range cs.Records {
		data := consentAppResponse{
			ID:                   c.ID,
			Status:               c.Status,
			Permissions:          c.Permissions,
			CreationDateTime:     timex.NewDateTime(c.CreatedAt),
			StatusUpdateDateTime: timex.NewDateTime(c.StatusUpdatedAt),
			RejectionReason:      c.RejectionReason,
			RejectedBy:           c.RejectedBy,
			UserID:               c.UserID,
			ClientID:             c.ClientID,
		}

		if c.ExpiresAt != nil {
			exp := timex.NewDateTime(*c.ExpiresAt)
			data.ExpirationDateTime = &exp
		}

		resp.Data = append(resp.Data, data)
	}

	return resp
}

func writeAppError(w http.ResponseWriter, err error) {
	api.WriteError(w, errBadRequest)
}
