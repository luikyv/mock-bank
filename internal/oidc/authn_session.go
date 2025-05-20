package oidc

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuthnSessionManager struct {
	coll *mongo.Collection
}

func NewAuthnSessionManager(database *mongo.Database) AuthnSessionManager {
	return AuthnSessionManager{
		coll: database.Collection("auth_sessions"),
	}
}

func (manager AuthnSessionManager) Save(ctx context.Context, session *goidc.AuthnSession) error {
	shouldUpsert := true
	filter := bson.D{bson.E{Key: "_id", Value: session.ID}}
	if _, err := manager.coll.ReplaceOne(
		ctx,
		filter,
		session,
		&options.ReplaceOptions{Upsert: &shouldUpsert},
	); err != nil {
		return err
	}

	return nil
}

func (m AuthnSessionManager) SessionByCallbackID(ctx context.Context, callbackID string) (*goidc.AuthnSession, error) {
	return m.getWithFilter(ctx, bson.D{bson.E{Key: "callback_id", Value: callbackID}})
}

func (m AuthnSessionManager) SessionByAuthCode(ctx context.Context, authorizationCode string) (*goidc.AuthnSession, error) {
	return m.getWithFilter(ctx, bson.D{bson.E{Key: "auth_code", Value: authorizationCode}})
}

func (m AuthnSessionManager) SessionByPushedAuthReqID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return m.getWithFilter(ctx, bson.D{bson.E{Key: "pushed_auth_req_id", Value: id}})
}

func (m AuthnSessionManager) SessionByCIBAAuthID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return nil, errors.ErrUnsupported
}

func (manager AuthnSessionManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{bson.E{Key: "_id", Value: id}}
	if _, err := manager.coll.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}

func (m AuthnSessionManager) getWithFilter(ctx context.Context, filter any) (*goidc.AuthnSession, error) {

	result := m.coll.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var authnSession goidc.AuthnSession
	if err := result.Decode(&authnSession); err != nil {
		return nil, err
	}

	return &authnSession, nil
}
