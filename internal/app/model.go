package app

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
)

const (
	cookieSessionId = "session_id"
	sessionValidity = 24 * time.Hour
)

type Session struct {
	ID            uuid.UUID `gorm:"primaryKey"`
	Username      string
	Organizations Organizations `gorm:"column:organizations;type:jsonb;not null"`

	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timex.Now())
}

type Organizations map[string]struct {
	Name string `json:"name"`
}

func (o Organizations) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *Organizations) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to convert value to []byte")
	}
	return json.Unmarshal(bytes, o)
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

func toUserResponse(s *Session) userResponse {
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

func (req mockUserRequest) toMockUser(orgID string) *user.User {
	return &user.User{
		Username: req.Username,
		Name:     req.Name,
		CPF:      req.CPF,
		OrgID:    orgID,
	}
}

type mockUserResponse struct {
	Data struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		CPF      string    `json:"cpf"`
		Name     string    `json:"name"`
	} `json:"data"`
	Meta  *api.Meta  `json:"meta"`
	Links *api.Links `json:"links"`
}

func toMockUserResponse(u *user.User, reqURL string) mockUserResponse {
	return mockUserResponse{
		Data: struct {
			ID       uuid.UUID `json:"id"`
			Username string    `json:"username"`
			CPF      string    `json:"cpf"`
			Name     string    `json:"name"`
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
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		CPF      string    `json:"cpf"`
		Name     string    `json:"name"`
	} `json:"data"`
	Meta  *api.Meta  `json:"meta"`
	Links *api.Links `json:"links"`
}

func toMockUsersResponse(us page.Page[*user.User], reqURL string) mockUsersResponse {
	resp := mockUsersResponse{
		Meta:  api.NewPaginatedMeta(us),
		Links: api.NewPaginatedLinks(reqURL, us),
	}

	resp.Data = []struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		CPF      string    `json:"cpf"`
		Name     string    `json:"name"`
	}{}
	for _, u := range us.Records {
		resp.Data = append(resp.Data, struct {
			ID       uuid.UUID `json:"id"`
			Username string    `json:"username"`
			CPF      string    `json:"cpf"`
			Name     string    `json:"name"`
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
	Links *api.Links        `json:"links"`
	Meta  *api.Meta         `json:"meta"`
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
	UserID               uuid.UUID               `json:"userId"`
	ClientID             string                  `json:"clientId"`
}

func toConsentsResponse(cs page.Page[*consent.Consent], reqURL string) consentsResponse {

	resp := consentsResponse{
		Data:  []consentResponse{},
		Meta:  api.NewPaginatedMeta(cs),
		Links: api.NewPaginatedLinks(reqURL, cs),
	}

	for _, c := range cs.Records {
		data := consentResponse{
			ID:                   c.URN(),
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

type accountResponse struct {
	Data []struct {
		AccountID   string       `json:"accountId"`
		BrandName   string       `json:"brandName"`
		CompanyCNPJ string       `json:"companyCnpj"`
		Type        account.Type `json:"type"`
		CompeCode   string       `json:"compeCode"`
		BranchCode  string       `json:"branchCode"`
		Number      string       `json:"number"`
		CheckDigit  string       `json:"checkDigit"`
	} `json:"data"`
	Meta  *api.Meta  `json:"meta"`
	Links *api.Links `json:"links"`
}

func toAccountsResponse(accs page.Page[*account.Account], reqURL string) accountResponse {
	resp := accountResponse{
		Meta:  api.NewPaginatedMeta(accs),
		Links: api.NewPaginatedLinks(reqURL, accs),
	}

	resp.Data = []struct {
		AccountID   string       `json:"accountId"`
		BrandName   string       `json:"brandName"`
		CompanyCNPJ string       `json:"companyCnpj"`
		Type        account.Type `json:"type"`
		CompeCode   string       `json:"compeCode"`
		BranchCode  string       `json:"branchCode"`
		Number      string       `json:"number"`
		CheckDigit  string       `json:"checkDigit"`
	}{}
	for _, acc := range accs.Records {
		resp.Data = append(resp.Data, struct {
			AccountID   string       `json:"accountId"`
			BrandName   string       `json:"brandName"`
			CompanyCNPJ string       `json:"companyCnpj"`
			Type        account.Type `json:"type"`
			CompeCode   string       `json:"compeCode"`
			BranchCode  string       `json:"branchCode"`
			Number      string       `json:"number"`
			CheckDigit  string       `json:"checkDigit"`
		}{
			AccountID: acc.ID,
			Type:      acc.Type,
			Number:    acc.Number,
		})
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
