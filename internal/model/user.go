package model

type User struct {
	username string
	displayName string
}

func NewUser(username string, displayName string) User {
	return User{username, displayName}
}
