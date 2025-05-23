package main

import (
	"log"
	"net/url"
)

func main() {
	a, err := url.Parse("http://localstack:4566/restapis/dfp5eio8dm/local/_user_request_")
	if err != nil {
		panic(err)
	}
	log.Println(a)
}
