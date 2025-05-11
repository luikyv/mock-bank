package swaggers

//go:generate oapi-codegen -config ./config.yml -package app -o ../internal/app/api_gen.go app.yml
//go:generate oapi-codegen -config ./config.yml -package v3 -o ../internal/opf/consent/v3/api_gen.go consents_v3.yml
//go:generate oapi-codegen -config ./config.yml -package v2 -o ../internal/opf/account/v2/api_gen.go accounts_v2.yml
