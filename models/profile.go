package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Profile model contains user profile information
type Profile struct {
	ID          string             `json:"ïd" bson:"_id"`
	AccountID   primitive.ObjectID `bson:"account_id"`
	DisplayName string             `json:"display_name" bson:"display_name" validate:"required"`
	Email       string             `json:"email" bson:"email" validate:"required,email"`
}
