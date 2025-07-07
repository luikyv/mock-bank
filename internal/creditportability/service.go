package creditportability

import (
	"github.com/luikyv/mock-bank/internal/creditop"
	"gorm.io/gorm"
)

type Service struct {
	db              *gorm.DB
	creditopService *creditop.Service
}

func NewService(db *gorm.DB, creditopService *creditop.Service) *Service {
	return &Service{db: db, creditopService: creditopService}
}
