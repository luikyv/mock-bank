package user

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/testutil"
)

func TestCreate(t *testing.T) {
	// Given.
	service := setup(t)

	tests := []struct {
		name    string
		user    *User
		wantErr error
	}{
		{
			name: "should create user successfully",
			user: &User{
				Username: "test@example.com",
				Name:     "Test User",
				CPF:      "12345678901",
				OrgID:    testutil.OrgID,
			},
			wantErr: nil,
		},
		{
			name: "should create user with CNPJ",
			user: &User{
				Username: "business@example.com",
				Name:     "Business User",
				CPF:      "12345678902",
				CNPJ:     testutil.PointerOf("12345678901234"),
				OrgID:    testutil.OrgID,
			},
			wantErr: nil,
		},
		{
			name: "should create user with description",
			user: &User{
				Username:    "desc@example.com",
				Name:        "Description User",
				CPF:         "12345678903",
				Description: testutil.PointerOf("Test description"),
				OrgID:       testutil.OrgID,
			},
			wantErr: nil,
		},
		{
			name: "should return error if user already exists",
			user: &User{
				Username: "test@example.com",
				Name:     "Test User 2",
				CPF:      "12345678901",
				OrgID:    testutil.OrgID,
			},
			wantErr: ErrAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			err := service.Create(context.Background(), tt.user)

			// Then.
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.user.ID == uuid.Nil {
				t.Error("expected user ID to be set")
			}
			if tt.user.CreatedAt.IsZero() {
				t.Error("expected CreatedAt to be set")
			}
			if tt.user.UpdatedAt.IsZero() {
				t.Error("expected UpdatedAt to be set")
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	// Given.
	service := setup(t)

	user := &User{
		Username: "update@example.com",
		Name:     "Update User",
		CPF:      "12345678904",
		OrgID:    testutil.OrgID,
	}
	err := service.Create(context.Background(), user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	tests := []struct {
		name    string
		updates *User
		wantErr error
	}{
		{
			name: "should update user name",
			updates: &User{
				ID:       user.ID,
				Username: "updated@example.com",
				Name:     "Updated Name",
				CPF:      "12345678904",
				OrgID:    testutil.OrgID,
			},
			wantErr: nil,
		},
		{
			name: "should update user with CNPJ",
			updates: &User{
				ID:       user.ID,
				Username: "updated@example.com",
				Name:     "Updated Name",
				CPF:      "12345678904",
				CNPJ:     testutil.PointerOf("98765432109876"),
				OrgID:    testutil.OrgID,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			err := service.Update(context.Background(), tt.updates)

			// Then.
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			updated, err := service.User(context.Background(), Query{ID: user.ID.String()}, testutil.OrgID)
			if err != nil {
				t.Fatalf("failed to get updated user: %v", err)
			}
			if updated.Username != tt.updates.Username {
				t.Errorf("got username %s, want %s", updated.Username, tt.updates.Username)
			}
			if updated.Name != tt.updates.Name {
				t.Errorf("got name %s, want %s", updated.Name, tt.updates.Name)
			}
			if tt.updates.CNPJ != nil {
				if updated.CNPJ == nil || *updated.CNPJ != *tt.updates.CNPJ {
					t.Errorf("got CNPJ %v, want %s", updated.CNPJ, *tt.updates.CNPJ)
				}
			}
			if updated.CreatedAt != user.CreatedAt {
				t.Errorf("got CreatedAt %s, want %s", updated.CreatedAt.String(), user.CreatedAt.String())
			}
			if updated.UpdatedAt.Before(user.UpdatedAt) {
				t.Errorf("got UpdatedAt %s, want after %s", updated.UpdatedAt.String(), user.UpdatedAt.String())
			}
		})
	}
}

func TestUser(t *testing.T) {
	// Given.
	service := setup(t)

	user1 := &User{
		Username: "query1@example.com",
		Name:     "Query User 1",
		CPF:      "11111111111",
		OrgID:    testutil.OrgID,
	}
	err := service.Create(context.Background(), user1)
	if err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}

	user2 := &User{
		Username: "query2@example.com",
		Name:     "Query User 2",
		CPF:      "22222222222",
		CNPJ:     testutil.PointerOf("11111111111111"),
		OrgID:    "mock-org-id2",
	}
	err = service.Create(context.Background(), user2)
	if err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	tests := []struct {
		name    string
		query   Query
		orgID   string
		wantErr error
	}{
		{
			name:    "should find user by ID",
			query:   Query{ID: user1.ID.String()},
			orgID:   testutil.OrgID,
			wantErr: nil,
		},
		{
			name:    "should find user by CPF",
			query:   Query{CPF: user1.CPF},
			orgID:   testutil.OrgID,
			wantErr: nil,
		},
		{
			name:    "should find user by username",
			query:   Query{Username: user1.Username},
			orgID:   testutil.OrgID,
			wantErr: nil,
		},
		{
			name:    "should find user by CNPJ",
			query:   Query{CNPJ: *user2.CNPJ},
			orgID:   user2.OrgID,
			wantErr: nil,
		},
		{
			name:    "should find user belonging to mock org when org id is different",
			query:   Query{ID: user1.ID.String()},
			orgID:   "random-org-id",
			wantErr: nil,
		},
		{
			name:    "should return error for non-existent user",
			query:   Query{ID: uuid.New().String()},
			orgID:   testutil.OrgID,
			wantErr: ErrNotFound,
		},
		{
			name:    "should return error for wrong org when user does not belong to mock org",
			query:   Query{ID: user2.ID.String()},
			orgID:   "wrong-org-id",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When.
			user, err := service.User(context.Background(), tt.query, tt.orgID)

			// Then.
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user == nil {
				t.Error("expected user to be returned")
			}
		})
	}
}

func TestUsers(t *testing.T) {
	// Given.
	service := setup(t)

	users := []*User{
		{Username: "list1@example.com", Name: "List User 1", CPF: "33333333333", OrgID: "mock-org-id1"},
		{Username: "list2@example.com", Name: "List User 2", CPF: "44444444444", OrgID: "mock-org-id1"},
		{Username: "list3@example.com", Name: "List User 3", CPF: "55555555555", OrgID: "mock-org-id1"},
	}

	for _, u := range users {
		err := service.Create(context.Background(), u)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
	}

	t.Run("should list users with pagination", func(t *testing.T) {
		// When.
		page, err := service.Users(context.Background(), "mock-org-id1", page.Pagination{Number: 1, Size: 2})

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(page.Records) != 2 {
			t.Errorf("expected 2 records, got %d", len(page.Records))
		}
		if page.TotalRecords < 3 {
			t.Errorf("expected at least 3 total records, got %d", page.TotalRecords)
		}
		if page.Number != 1 {
			t.Errorf("expected page number 1, got %d", page.Number)
		}
		if page.Size != 2 {
			t.Errorf("expected page size 2, got %d", page.Size)
		}
	})

	t.Run("should return empty page for wrong org", func(t *testing.T) {
		// When.
		page, err := service.Users(context.Background(), "wrong-org", page.Pagination{Number: 1, Size: 10})

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(page.Records) != 0 {
			t.Errorf("got %d records, want 0", len(page.Records))
		}
		if page.TotalRecords != 0 {
			t.Errorf("got %d total records, want 0", page.TotalRecords)
		}
	})
}

func TestDelete(t *testing.T) {
	// Given.
	service := setup(t)

	user := &User{
		Username: "delete@example.com",
		Name:     "Delete User",
		CPF:      "66666666666",
		OrgID:    testutil.OrgID,
	}
	err := service.Create(context.Background(), user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	t.Run("should delete user successfully", func(t *testing.T) {
		// When.
		err := service.Delete(context.Background(), user.ID, testutil.OrgID)

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = service.User(context.Background(), Query{ID: user.ID.String()}, testutil.OrgID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("should not delete user from wrong org", func(t *testing.T) {
		// Given.
		err := service.Create(context.Background(), user)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		// When.
		err = service.Delete(context.Background(), user.ID, "wrong-org")

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = service.User(context.Background(), Query{ID: user.ID.String()}, "wrong-org")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestUserBusiness(t *testing.T) {
	// Given.
	service := setup(t)

	business := &User{
		Username: "business@example.com",
		Name:     "Business User",
		CPF:      "88888888888",
		CNPJ:     testutil.PointerOf("12345678901234"),
		OrgID:    testutil.OrgID,
	}
	err := service.Create(context.Background(), business)
	if err != nil {
		t.Fatalf("failed to create business: %v", err)
	}

	user := &User{
		Username: "regular@example.com",
		Name:     "Regular User",
		CPF:      "99999999999",
		OrgID:    testutil.OrgID,
	}
	err = service.Create(context.Background(), user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	t.Run("should return business when user is the business owner", func(t *testing.T) {
		// When.
		result, err := service.Business(context.Background(), business.ID.String(), *business.CNPJ, testutil.OrgID)

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != business.ID {
			t.Errorf("got %s, want %s", result.ID, business.ID)
		}
	})

	t.Run("should return error when user doesn't own business", func(t *testing.T) {
		// When.
		_, err := service.Business(context.Background(), user.ID.String(), *business.CNPJ, testutil.OrgID)

		// Then.
		if !errors.Is(err, ErrUserDoesNotOwnBusiness) {
			t.Errorf("got %v, want ErrUserDoesNotOwnBusiness", err)
		}
	})

	t.Run("should return error when business doesn't exist", func(t *testing.T) {
		// When.
		_, err := service.Business(context.Background(), user.ID.String(), "00000000000000", testutil.OrgID)

		// Then.
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}

func TestBindUserToBusiness(t *testing.T) {
	// Given.
	service := setup(t)

	business := &User{
		Username: "bindbusiness@example.com",
		Name:     "Bind Business User",
		CPF:      "10101010101",
		CNPJ:     testutil.PointerOf("98765432109876"),
		OrgID:    testutil.OrgID,
	}
	err := service.Create(context.Background(), business)
	if err != nil {
		t.Fatalf("failed to create business: %v", err)
	}

	user := &User{
		Username: "binduser@example.com",
		Name:     "Bind User",
		CPF:      "20202020202",
		OrgID:    testutil.OrgID,
	}
	err = service.Create(context.Background(), user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	t.Run("should bind user to business successfully", func(t *testing.T) {
		// When.
		err := service.BindUserToBusiness(context.Background(), user.ID, business.ID, testutil.OrgID)

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := service.Business(context.Background(), user.ID.String(), *business.CNPJ, testutil.OrgID)
		if err != nil {
			t.Fatalf("failed to verify binding: %v", err)
		}
		if result.ID != business.ID {
			t.Errorf("got %s, want %s", result.ID, business.ID)
		}
	})

	t.Run("should handle duplicate binding gracefully", func(t *testing.T) {
		// When.
		err := service.BindUserToBusiness(context.Background(), user.ID, business.ID, testutil.OrgID)

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("should return error for non-existent business", func(t *testing.T) {
		// When.
		err := service.BindUserToBusiness(context.Background(), user.ID, uuid.New(), testutil.OrgID)

		// Then.
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("should return error for non-existent user", func(t *testing.T) {
		// When.
		err := service.BindUserToBusiness(context.Background(), uuid.New(), business.ID, testutil.OrgID)

		// Then.
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("should return error for wrong org", func(t *testing.T) {
		// Given.
		otherUser := &User{
			Username: "other@example.com",
			Name:     "Other User",
			CPF:      "30303030303",
			OrgID:    "other-org",
		}
		err := service.Create(context.Background(), otherUser)
		if err != nil {
			t.Fatalf("failed to create other user: %v", err)
		}

		// When.
		err = service.BindUserToBusiness(context.Background(), otherUser.ID, business.ID, "other-org")

		// Then.
		if !errors.Is(err, ErrInvalidOrgID) {
			t.Errorf("got %v, want ErrInvalidOrgID", err)
		}
	})
}

func setup(t *testing.T) Service {
	db := testutil.NewDB(t)
	return NewService(db, testutil.OrgID)
}
