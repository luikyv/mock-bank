package account

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Storage struct {
	coll *mongo.Collection
}

func NewStorage(db *mongo.Database) Storage {
	return Storage{
		coll: db.Collection("accounts"),
	}
}

func (s Storage) save(ctx context.Context, acc Account) error {
	shouldUpsert := true
	filter := bson.D{{Key: "_id", Value: acc.ID}}
	if _, err := s.coll.ReplaceOne(ctx, filter, acc, &options.ReplaceOptions{
		Upsert: &shouldUpsert,
	}); err != nil {
		return err
	}
	return nil
}

func (s Storage) account(ctx context.Context, id string) (Account, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	result := s.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return Account{}, errNotFound
	}

	var acc Account
	if err := result.Decode(&acc); err != nil {
		return Account{}, fmt.Errorf("could not decode account with id %s: %w", id, err)
	}

	return acc, nil
}

func (s Storage) accountsByUserID(ctx context.Context, id string) ([]Account, error) {
	return s.filterAccounts(ctx, bson.D{{Key: "user_id", Value: id}})
}

func (s Storage) accounts(ctx context.Context, ids []string) ([]Account, error) {
	return s.filterAccounts(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}})
}

func (s Storage) filterAccounts(ctx context.Context, filter any) ([]Account, error) {
	cursor, err := s.coll.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("could not find accounts: %w", err)
	}
	defer cursor.Close(ctx)

	var accs []Account
	if err := cursor.All(ctx, &accs); err != nil {
		return nil, fmt.Errorf("could not decode accounts: %w", err)
	}

	return accs, nil
}
