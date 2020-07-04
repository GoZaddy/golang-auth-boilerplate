package models

import "go.mongodb.org/mongo-driver/bson/primitive"

const (
	EMAIL  = "EMAIL"
	GOOGLE = "GOOGLE"
	GITHUB = "GITHUB"
)

//EmailAuth Model
type EmailAuth struct {
	Password []byte `bson:"password" json:"password" validate:"omitempty,required"`
}

//GoogleAuth Model
type GoogleAuth struct {
	ID string `bson:"id" validate:"omitempty,required,gt=1"` //sub
}

//GithubAuth Model
type GithubAuth struct {
	ID string `bson:"id" validate:"omitempty,required,gt=1"` //node_id
}

//Account Model contains user account information
type Account struct {
	ID                primitive.ObjectID `bson:"_id" validate:"required"`
	Email             string             `bson:"email" validate:"required,email"`
	AuthProviders     []string           `bson:"auth_providers" validate:"required"`
	EmailAuthDetails  *EmailAuth         `bson:"email_auth_details,omitempty" validate:"omitempty,dive"`
	GoogleAuthDetails *GoogleAuth        `bson:"google_auth_details,omitempty" vaidate:"omitempty,dive"`
	GithubAuthDetails *GithubAuth        `bson:"github_auth_details,omitempty" vaidate:"omitempty,dive"`
	ProfileID         primitive.ObjectID `bson:"profile_id" validate:"required"`
}
