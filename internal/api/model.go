package api

import (
	"net/url"
	"strconv"

	"github.com/luiky/mock-bank/internal/page"
	"github.com/luiky/mock-bank/internal/timex"
)

type ContextKey string

const (
	CtxKeyClientID      ContextKey = "client_id"
	CtxKeySubject       ContextKey = "subject"
	CtxKeyScopes        ContextKey = "scopes"
	CtxKeyConsentID     ContextKey = "consent_id"
	CtxKeyInteractionID ContextKey = "interaction_id"
	CtxKeyRequestURL    ContextKey = "request_url"
	CtxKeyOrgID         ContextKey = "org_id"
)

const (
	maxPageSize int = 25
)

const (
	HeaderCustomerIPAddress = "X-FAPI-Customer-IP-Address"
	HeaderCustomerUserAgent = "X-Customer-User-Agent"
)

// // TODO: Remove this.
// func NewPagination(r *http.Request) (page.Pagination, error) {
// 	pageNumber := 1
// 	pageSize := maxPageSize

// 	// Get "page" query parameter and convert it to an integer.
// 	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
// 		if p, err := strconv.Atoi(pageStr); err == nil {
// 			pageNumber = p
// 		}
// 	}

// 	if pageNumber < 1 {
// 		return page.Pagination{}, NewError("INVALID_PARAMETER", http.StatusBadRequest, "invalid page number")
// 	}

// 	// Get "page-size" query parameter and convert it to an integer.
// 	if pageSizeStr := r.URL.Query().Get("page-size"); pageSizeStr != "" {
// 		if ps, err := strconv.Atoi(pageSizeStr); err == nil {
// 			pageSize = ps
// 		}
// 	}

// 	if pageSize < 0 || pageSize > 1000 {
// 		return page.Pagination{}, NewError("INVALID_PARAMETER", http.StatusBadRequest, "invalid page size")
// 	}

// 	if pageSize > maxPageSize {
// 		pageSize = maxPageSize
// 	}

// 	return page.NewPagination(pageNumber, pageSize), nil
// }

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
func NewPaginatedLinks[T any](requestedURL string, page page.Page[T]) *Links {
	// Helper function to construct a URL with query parameters for pagination.
	buildURL := func(pageNumber int) string {
		u, _ := url.Parse(requestedURL)
		query := u.Query()
		query.Set("page", strconv.Itoa(pageNumber))
		query.Set("page-size", strconv.Itoa(page.Size))
		u.RawQuery = query.Encode()
		return u.String()
	}

	// Populate the Links struct.
	links := &Links{
		Self: requestedURL,
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
	RequestDateTime timex.DateTime `json:"requestDateTime"`
	TotalRecords    *int           `json:"totalRecords,omitempty"`
	TotalPages      *int           `json:"totalPages,omitempty"`
}

func NewMeta() *Meta {
	return &Meta{
		RequestDateTime: timex.DateTimeNow(),
	}
}

func NewPaginatedMeta[T any](p page.Page[T]) *Meta {
	return &Meta{
		RequestDateTime: timex.DateTimeNow(),
		TotalRecords:    &p.TotalRecords,
		TotalPages:      &p.TotalPages,
	}
}

func NewSingleRecordMeta() *Meta {
	one := 1
	return &Meta{
		RequestDateTime: timex.DateTimeNow(),
		TotalRecords:    &one,
		TotalPages:      &one,
	}
}
