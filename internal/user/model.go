package user

type User struct {
	ID       string `bson:"_id"`
	Username string `bson:"username"`
	OrgID    string `bson:"org_id"`
	CPF      string `bson:"cpf"`
}
