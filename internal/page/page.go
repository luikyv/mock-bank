package page

import (
	"fmt"

	"gorm.io/gorm"
)

const (
	defaultPageSize = 25
)

type Page[T any] struct {
	// Records are the records found for the page requested.
	Records []T
	// TotalRecords is the total number of records available.
	TotalRecords int
	// TotalPages is the total number of pages based on Size and TotalRecords.
	TotalPages int
	Pagination
}

func New[T any](records []T, pagination Pagination, totalRecords int) Page[T] {
	return Page[T]{
		Records:      records,
		TotalRecords: totalRecords,
		// Adding (pagination.Size - 1) ensures a correct rounding up for partial pages.
		TotalPages: (totalRecords + pagination.Size - 1) / pagination.Size,
		Pagination: pagination,
	}
}

type Pagination struct {
	// Number is the page number requested starting from 1.
	Number int
	// Size is the page size requested.
	Size int
}

// Offset returns the zero-based offset.
func (p Pagination) Offset() int {
	if p.Number <= 1 {
		return 0
	}
	return (p.Number - 1) * p.Size
}

// Limit returns the number of items to retrieve.
func (p Pagination) Limit() int {
	return p.Size
}

func NewPagination(pageNumber *int32, pageSize *int32) Pagination {
	pagination := Pagination{
		Number: 1,
		Size:   defaultPageSize,
	}

	if pageNumber != nil && *pageNumber > 0 {
		pagination.Number = int(*pageNumber)
	}

	if pageSize != nil && *pageSize > 0 && *pageSize <= defaultPageSize {
		pagination.Size = int(*pageSize)
	}

	return pagination
}

func Paginate[T any](query *gorm.DB, pag Pagination) (Page[T], error) {
	var records []T
	if err := query.
		Limit(pag.Limit()).
		Offset(pag.Offset()).
		Find(&records).Error; err != nil {
		return Page[T]{}, fmt.Errorf("failed to find records: %w", err)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return Page[T]{}, fmt.Errorf("failed to count records: %w", err)
	}

	return New(records, pag, int(total)), nil
}
