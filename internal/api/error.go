package api

import (
	"errors"
	"fmt"
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

func NewError(code string, status int, description string) Error {
	err := Error{
		code:        code,
		statusCode:  status,
		description: description,
	}

	return err
}

func WriteError(w http.ResponseWriter, err error) {
	var apiErr Error
	if !errors.As(err, &apiErr) {
		WriteError(w, Error{"INTERNAL_ERROR", http.StatusInternalServerError, "internal error", false})
		return
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
				Detail: apiErr.description,
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
	Meta Meta `json:"meta"`
}
