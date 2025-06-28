package client

import (
	"context"

	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) Service {
	return Service{db: db}
}

func (s Service) Save(ctx context.Context, client *Client) error {
	return s.db.WithContext(ctx).Omit("CreatedAt").Save(client).Error
}

func (s Service) Client(ctx context.Context, id string) (*Client, error) {
	var client Client
	if err := s.db.WithContext(ctx).First(&client, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s Service) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&Client{}, "id = ?", id).Error
}
