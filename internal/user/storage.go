package user

import (
	"context"
	"log"

	"github.com/luiky/mock-bank/internal/page"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Storage struct {
	coll *mongo.Collection
}

func NewStorage(db *mongo.Database) Storage {
	coll := db.Collection("users")

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "org_id", Value: 1}, {Key: "_id", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("unique_orgid_id"),
		},
		{
			Keys:    bson.D{{Key: "org_id", Value: 1}, {Key: "cpf", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("unique_orgid_cpf"),
		},
		{
			Keys:    bson.D{{Key: "org_id", Value: 1}, {Key: "username", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("unique_orgid_username"),
		},
	}

	// TODO: Handle this error properly.
	_, err := coll.Indexes().CreateMany(context.Background(), indexes)
	if err != nil {
		log.Fatalf("failed to create indexes: %v", err)
	}

	return Storage{
		coll: coll,
	}
}

func (s Storage) save(ctx context.Context, u User) error {
	shouldUpsert := true
	filter := bson.D{{Key: "_id", Value: u.ID}}
	if _, err := s.coll.ReplaceOne(ctx, filter, u, &options.ReplaceOptions{
		Upsert: &shouldUpsert,
	}); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (s Storage) user(ctx context.Context, id, orgID string) (User, error) {
	filter := bson.D{{Key: "_id", Value: id}, {Key: "org_id", Value: orgID}}
	return s.filterUser(ctx, filter)
}

func (s Storage) userByCPF(ctx context.Context, cpf, orgID string) (User, error) {
	filter := bson.D{{Key: "cpf", Value: cpf}, {Key: "org_id", Value: orgID}}
	return s.filterUser(ctx, filter)
}

func (s Storage) userByUsername(ctx context.Context, username, orgID string) (User, error) {
	filter := bson.D{{Key: "username", Value: username}, {Key: "org_id", Value: orgID}}
	return s.filterUser(ctx, filter)
}

func (s Storage) users(ctx context.Context, orgID string, pag page.Pagination) (page.Page[User], error) {
	filter := bson.D{{Key: "org_id", Value: orgID}}
	cursor, err := s.coll.Find(ctx, filter)
	if err != nil {
		return page.Page[User]{}, err
	}
	defer cursor.Close(ctx)

	var us []User
	if err := cursor.All(ctx, &us); err != nil {
		return page.Page[User]{}, err
	}

	return page.Paginate(us, pag), nil
}

func (s Storage) filterUser(ctx context.Context, filter any) (User, error) {
	result := s.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return User{}, ErrNotFound
	}

	var u User
	if err := result.Decode(&u); err != nil {
		return User{}, err
	}

	return u, nil
}

func (s Storage) delete(ctx context.Context, id, orgID string) error {
	filter := bson.D{{Key: "_id", Value: id}, {Key: "org_id", Value: orgID}}
	if _, err := s.coll.DeleteOne(ctx, filter); err != nil {
		return err
	}
	return nil
}
