package auth

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Storage struct {
	coll *mongo.Collection
}

func NewStorage(db *mongo.Database) Storage {
	return Storage{
		coll: db.Collection("user_sessions"),
	}
}

func (st Storage) createSession(ctx context.Context, s Session) error {
	if _, err := st.coll.InsertOne(ctx, s); err != nil {
		return fmt.Errorf("could not create session: %w", err)
	}
	return nil
}

func (st Storage) session(ctx context.Context, id string) (Session, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	result := st.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return Session{}, errNotFound
	}

	var s Session
	if err := result.Decode(&s); err != nil {
		return Session{}, fmt.Errorf("could not decode session with id %s: %w", id, err)
	}

	return s, nil
}

func (st Storage) deleteSession(ctx context.Context, id string) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := st.coll.DeleteOne(ctx, filter); err != nil {
		return fmt.Errorf("could not delete session with id %s: %w", id, err)
	}
	return nil
}
