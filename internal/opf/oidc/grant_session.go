package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TODO: Make sure this is working as expected.

type GrantSessionManager struct {
	coll *mongo.Collection
}

func NewGrantSessionManager(database *mongo.Database) GrantSessionManager {
	return GrantSessionManager{
		coll: database.Collection("grant_sessions"),
	}
}

func (manager GrantSessionManager) Save(ctx context.Context, grantSession *goidc.GrantSession) error {
	shouldReplace := true
	filter := bson.D{bson.E{Key: "_id", Value: grantSession.ID}}
	if _, err := manager.coll.ReplaceOne(
		ctx,
		filter,
		grantSession,
		&options.ReplaceOptions{Upsert: &shouldReplace},
	); err != nil {
		return err
	}

	return nil
}

func (manager GrantSessionManager) SessionByTokenID(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return manager.getWithFilter(ctx, bson.D{bson.E{Key: "token_id", Value: id}})
}

func (manager GrantSessionManager) SessionByRefreshTokenID(ctx context.Context, token string) (*goidc.GrantSession, error) {
	return manager.getWithFilter(
		ctx,
		bson.D{bson.E{Key: "refresh_token", Value: token}},
	)
}

func (manager GrantSessionManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{bson.E{Key: "_id", Value: id}}
	if _, err := manager.coll.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}

func (m GrantSessionManager) DeleteByAuthCode(context.Context, string) error {
	return nil
}

func (manager GrantSessionManager) getWithFilter(ctx context.Context, filter any) (*goidc.GrantSession, error) {

	result := manager.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var grantSession goidc.GrantSession
	if err := result.Decode(&grantSession); err != nil {
		return nil, err
	}

	return &grantSession, nil
}
