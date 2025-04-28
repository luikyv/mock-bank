package consent

import (
	"context"
	"fmt"

	"github.com/luiky/mock-bank/internal/page"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Storage struct {
	coll *mongo.Collection
}

func NewStorage(db *mongo.Database) Storage {
	return Storage{
		coll: db.Collection("consents"),
	}
}

func (s Storage) save(ctx context.Context, c Consent) error {
	shouldUpsert := true
	filter := bson.D{{Key: "_id", Value: c.ID}}
	if _, err := s.coll.ReplaceOne(ctx, filter, c, &options.ReplaceOptions{
		Upsert: &shouldUpsert,
	}); err != nil {
		return err
	}
	return nil
}

func (s Storage) consent(ctx context.Context, id string) (Consent, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	result := s.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return Consent{}, errNotFound
	}

	var c Consent
	if err := result.Decode(&c); err != nil {
		return Consent{}, err
	}

	return c, nil
}

func (s Storage) extensions(ctx context.Context, id string, pag page.Pagination) (page.Page[Extension], error) {
	c, err := s.consent(ctx, id)
	if err != nil {
		return page.Page[Extension]{}, err
	}

	return page.Paginate(c.Extensions, pag), nil
}

func (s Storage) consents(ctx context.Context, userID, orgID string, pag page.Pagination) (page.Page[Consent], error) {
	cursor, err := s.coll.Find(ctx, bson.D{{Key: "user_id", Value: userID}, {Key: "org_id", Value: orgID}})
	if err != nil {
		return page.Page[Consent]{}, fmt.Errorf("could not load consents: %w", err)
	}
	defer cursor.Close(ctx)

	var cs []Consent
	if err := cursor.All(ctx, &cs); err != nil {
		return page.Page[Consent]{}, fmt.Errorf("could not decode consents: %w", err)
	}

	return page.Paginate(cs, pag), nil
}
