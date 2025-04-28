package page

type Page[T any] struct {
	// Records are the records found for the page requested.
	Records []T
	// TotalRecords is the total number of records available.
	TotalRecords int
	// TotalPages is the total number of pages based on Size and TotalRecords.
	TotalPages int
	Pagination
}

type Pagination struct {
	// Number is the page number requested.
	Number int
	// Size is the page size requested.
	Size int
}

// Offset calculates the offset based on the page number and size.
// Subtract 1 from the page number to convert it to a zero-based index.
func (p Pagination) Offset() int {
	return (p.Number - 1) * p.Size
}

func NewPagination(pageNumber int, pageSize int) Pagination {
	pagination := Pagination{
		Number: 1,
		Size:   25,
	}

	if pageNumber != 0 {
		pagination.Number = pageNumber
	}

	if pageSize != 0 && pageSize <= 1000 {
		pagination.Size = pageSize
	}

	return pagination
}

// Paginate slices a list of records into a specific page of data based on the
// provided pagination parameters.
func Paginate[T any](records []T, pagination Pagination) Page[T] {
	numberOfRecords := len(records)
	page := Page[T]{
		TotalRecords: numberOfRecords,
		// Calculate the total number of pages using integer division.
		// Adding (pagination.Size - 1) ensures correct rounding up for partial pages.
		TotalPages: (numberOfRecords + pagination.Size - 1) / pagination.Size,
		Pagination: pagination,
	}

	// Subtracting 1 from the page number to convert it to a zero-based index,
	// as pages start at 1.
	start := (page.Number - 1) * page.Size
	if start >= numberOfRecords {
		return page
	}

	end := min(start+page.Size, numberOfRecords)

	page.Records = records[start:end]
	return page
}
