package api

import (
	"net/url"
	"strconv"

	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

type ContextKey string

const (
	CtxKeyCorrelationID ContextKey = "correlation_id"
	CtxKeyClientID      ContextKey = "client_id"
	CtxKeySubject       ContextKey = "subject"
	CtxKeyScopes        ContextKey = "scopes"
	CtxKeyConsentID     ContextKey = "consent_id"
	CtxKeyInteractionID ContextKey = "interaction_id"
	CtxKeyOrgID         ContextKey = "org_id"
	CtxKeySessionID     ContextKey = "session_id"
)

const (
	HeaderCustomerIPAddress  = "X-FAPI-Customer-IP-Address"
	HeaderCustomerUserAgent  = "X-Customer-User-Agent"
	HeaderXFAPIInteractionID = "X-FAPI-Interaction-ID"
)

type Links struct {
	First string `json:"first,omitempty"`
	Last  string `json:"last,omitempty"`
	Next  string `json:"next,omitempty"`
	Prev  string `json:"prev,omitempty"`
	Self  string `json:"self"`
}

func NewLinks(self string) *Links {
	return &Links{
		Self: self,
	}
}

// NewPaginatedLinks generates pagination links (self, first, prev, next, last) based on
// the current page information and the requested URL.
func NewPaginatedLinks[T any](self string, page page.Page[T]) *Links {
	// Helper function to construct a URL with query parameters for pagination.
	buildURL := func(pageNumber int) string {
		u, _ := url.Parse(self)
		query := u.Query()
		query.Set("page", strconv.Itoa(pageNumber))
		query.Set("page-size", strconv.Itoa(page.Size))
		u.RawQuery = query.Encode()
		return u.String()
	}

	// Populate the Links struct.
	links := &Links{
		Self: self,
	}

	// If the current page is not the first, generate the "first" and "previous"
	// links.
	if page.Number > 1 {
		links.First = buildURL(1)
		links.Prev = buildURL(page.Number - 1)
	}

	// If the current page is not the last, generate the "next" and "last" links.
	if page.Number < page.TotalPages {
		links.Next = buildURL(page.Number + 1)
		links.Last = buildURL(page.TotalPages)
	}

	return links
}

type Meta struct {
	RequestDateTime timeutil.DateTime `json:"requestDateTime"`
	TotalRecords    *int              `json:"totalRecords,omitempty"`
	TotalPages      *int              `json:"totalPages,omitempty"`
}

func NewMeta() *Meta {
	return &Meta{
		RequestDateTime: timeutil.DateTimeNow(),
	}
}

func NewPaginatedMeta[T any](p page.Page[T]) *Meta {
	return &Meta{
		RequestDateTime: timeutil.DateTimeNow(),
		TotalRecords:    &p.TotalRecords,
		TotalPages:      &p.TotalPages,
	}
}

func NewSingleRecordMeta() *Meta {
	one := 1
	return &Meta{
		RequestDateTime: timeutil.DateTimeNow(),
		TotalRecords:    &one,
		TotalPages:      &one,
	}
}
