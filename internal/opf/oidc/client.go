package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ClientManager struct {
	coll *mongo.Collection
}

func NewClientManager(database *mongo.Database) ClientManager {
	return ClientManager{
		coll: database.Collection("clients"),
	}
}

func (manager ClientManager) Save(ctx context.Context, client *goidc.Client) error {
	shouldUpsert := true
	filter := bson.D{bson.E{Key: "_id", Value: client.ID}}
	if _, err := manager.coll.ReplaceOne(ctx, filter, client, &options.ReplaceOptions{Upsert: &shouldUpsert}); err != nil {
		return err
	}

	return nil
}

func (manager ClientManager) Client(ctx context.Context, id string) (*goidc.Client, error) {
	filter := bson.D{bson.E{Key: "_id", Value: id}}

	result := manager.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var client goidc.Client
	if err := result.Decode(&client); err != nil {
		return nil, err
	}

	return &client, nil
}

func (manager ClientManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{bson.E{Key: "_id", Value: id}}
	if _, err := manager.coll.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}
