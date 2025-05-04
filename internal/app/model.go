package app

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luiky/mock-bank/internal/user"
)

const (
	cookieSessionId = "session_id"
	sessionValidity = 24 * time.Hour
)

type Session struct {
	ID            string                  `bson:"_id"`
	Username      string                  `bson:"username"`
	Organizations map[string]Organization `bson:"organizations"`
	CreatedAt     timex.DateTime          `bson:"created_at"`
	ExpiresAt     timex.DateTime          `bson:"expires_at"`
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timex.Now())
}

type Organization struct {
	Name string `bson:"name"`
}

type directoryIDToken struct {
	Sub     string `json:"sub"`
	Profile struct {
		OrgAccessDetails map[string]struct {
			Name    string `json:"organisation_name"`
			IsAdmin bool   `json:"org_admin"`
		} `json:"org_access_details"`
	} `json:"trust_framework_profile"`
}

type directoryWellKnown struct {
	AuthEndpoint   string                    `json:"authorization_endpoint"`
	JWKSURI        string                    `json:"jwks_uri"`
	IDTokenSigAlgs []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}

type userResponse struct {
	Data struct {
		Username      string                     `json:"username"`
		Organizations map[string]userOrgResponse `json:"organizations"`
	} `json:"data"`
}

type userOrgResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func toUserResponse(s Session) userResponse {
	resp := userResponse{}
	resp.Data.Username = s.Username
	resp.Data.Organizations = map[string]userOrgResponse{}
	for orgID, org := range s.Organizations {
		resp.Data.Organizations[orgID] = userOrgResponse{
			ID:   orgID,
			Name: org.Name,
		}
	}

	return resp
}

type mockUserRequest struct {
	// TODO. Data.
	Username string `json:"username"`
	Name     string `json:"name"`
	CPF      string `json:"cpf"`
}

func (req mockUserRequest) toMockUser(orgID string) user.User {
	return user.User{
		ID:       uuid.NewString(),
		Username: req.Username,
		Name:     req.Name,
		CPF:      req.CPF,
		OrgID:    orgID,
	}
}

type mockUserResponse struct {
	Data struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		CPF      string `json:"cpf"`
		Name     string `json:"name"`
	} `json:"data"`
	Meta  api.Meta  `json:"meta"`
	Links api.Links `json:"links"`
}

func toMockUserResponse(u user.User, reqURL string) mockUserResponse {
	return mockUserResponse{
		Data: struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			CPF      string `json:"cpf"`
			Name     string `json:"name"`
		}{
			ID:       u.ID,
			Username: u.Username,
			Name:     u.Name,
			CPF:      u.CPF,
		},
		Links: api.NewLinks(reqURL),
		Meta:  api.NewMeta(),
	}
}

type mockUsersResponse struct {
	Data []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		CPF      string `json:"cpf"`
		Name     string `json:"name"`
	} `json:"data"`
	Meta  api.Meta  `json:"meta"`
	Links api.Links `json:"links"`
}

func toMockUsersResponse(us page.Page[user.User], reqURL string) mockUsersResponse {
	resp := mockUsersResponse{
		Meta:  api.NewPaginatedMeta(us),
		Links: api.NewPaginatedLinks(reqURL, us),
	}

	resp.Data = []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		CPF      string `json:"cpf"`
		Name     string `json:"name"`
	}{}
	for _, u := range us.Records {
		resp.Data = append(resp.Data, struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			CPF      string `json:"cpf"`
			Name     string `json:"name"`
		}{
			ID:       u.ID,
			Username: u.Username,
			CPF:      u.CPF,
			Name:     u.Name,
		})
	}

	return resp
}

type consentsResponse struct {
	Data  []consentResponse `json:"data"`
	Links api.Links         `json:"links"`
	Meta  api.Meta          `json:"meta"`
}

type consentResponse struct {
	ID                   string                  `json:"consentId"`
	Status               consent.Status          `json:"status"`
	Permissions          []consent.Permission    `json:"permissions"`
	CreationDateTime     timex.DateTime          `json:"creationDateTime"`
	StatusUpdateDateTime timex.DateTime          `json:"statusUpdateDateTime"`
	ExpirationDateTime   *timex.DateTime         `json:"expirationDateTime,omitempty"`
	RejectedBy           consent.RejectedBy      `json:"rejectedBy,omitempty"`
	RejectionReason      consent.RejectionReason `json:"rejectionReason,omitempty"`
	UserID               string                  `json:"userId"`
	ClientID             string                  `json:"clientId"`
}

func toConsentsResponse(cs page.Page[consent.Consent], reqURL string) consentsResponse {

	resp := consentsResponse{
		Data:  []consentResponse{},
		Meta:  api.NewPaginatedMeta(cs),
		Links: api.NewPaginatedLinks(reqURL, cs),
	}

	for _, c := range cs.Records {
		data := consentResponse{
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

type directoryAuthURLResponse struct {
	Data struct {
		AuthURL string `json:"authUrl"`
	} `json:"data"`
}

func toDirectoryAuthURLResponse(authURL string) directoryAuthURLResponse {
	return directoryAuthURLResponse{
		Data: struct {
			AuthURL string `json:"authUrl"`
		}{
			AuthURL: authURL,
		},
	}
}
