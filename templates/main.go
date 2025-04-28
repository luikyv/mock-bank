package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/luiky/mock-bank/internal/account"
)

type ConsentPageData struct {
	BaseURL      string
	CallbackID   string
	BusinessCNPJ string
	UserCPF      string
	Permissions  []string
	Accounts     []account.Account
	CreditCards  []string
}

func main() {
	tmpl := template.Must(template.ParseFiles("./consent.html"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := ConsentPageData{
			BaseURL:      "http://localhost:8080",
			CallbackID:   "mock-callback-id",
			BusinessCNPJ: "12.345.678/0001-90",
			UserCPF:      "", // Leave empty if BusinessCNPJ is filled
			// Accounts: []account.Account{
			// 	{ID: "acc-001", Number: "Account 1"},
			// },
			// CreditCards: []string{
			// 	"cc-101",
			// 	"cc-102",
			// },
		}

		err := tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Template rendering error", http.StatusInternalServerError)
			log.Println("Template error:", err)
		}
	})

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
