package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type Error struct {
	code        string
	statusCode  int
	description string
	pagination  bool
}

func (err Error) Error() string {
	return fmt.Sprintf("%s %s", err.code, err.description)
}

func (err Error) WithPagination() Error {
	err.pagination = true
	return err
}

func (err Error) Pagination(b bool) Error {
	err.pagination = b
	return err
}

func NewError(code string, status int, description string) Error {
	err := Error{
		code:        code,
		statusCode:  status,
		description: description,
	}

	return err
}

// WriteError writes an API error response to the provided http.ResponseWriter.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr Error
	if !errors.As(err, &apiErr) {
		slog.ErrorContext(r.Context(), "unknown error", "error", err)
		WriteError(w, r, Error{"INTERNAL_ERROR", http.StatusInternalServerError, "internal error", false})
		return
	}

	slog.InfoContext(r.Context(), "returning error", "error", err, "status_code", apiErr.statusCode)
	description := apiErr.description
	if len(description) > 2048 {
		description = description[:2048]
	}
	errResp := response{
		Errors: []struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}{
			{
				Code:   apiErr.code,
				Title:  apiErr.code,
				Detail: description,
			},
		},
		Meta: NewMeta(),
	}
	if apiErr.pagination {
		errResp.Meta = NewSingleRecordMeta()
	}

	WriteJSON(w, errResp, apiErr.statusCode)
}

type response struct {
	Errors []struct {
		Code   string `json:"code"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	} `json:"errors"`
	Meta *Meta `json:"meta"`
}
