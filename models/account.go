package models

import "go.mongodb.org/mongo-driver/bson/primitive"

const (
	EMAIL  = "EMAIL"
	GOOGLE = "GOOGLE"
)

//EmailAuth Model
type EmailAuth struct {
	Email    string `bson:"email" json:"email" validate:"required,email"`
	Password []byte `bson:"password" json:"password" validate:"required"`
}

//GoogleAuth Model
type GoogleAuth struct {
	ID    string `bson:"id" validate:"required"`
	Email string `bson:"email" validate:"required,email"`
}

//Account Model contains user account information
type Account struct {
	ID               primitive.ObjectID `bson:"_id" validate:"required"`
	AuthMethod       string             `bson:"auth_method" validate:"required"`
	EmailAuthDetails EmailAuth          `bson:"email_auth_details" validate:"required,dive"`
	ProfileID        string             `bson:"profile_id" validate:"required"`
}
