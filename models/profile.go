package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Profile model contains user profile information
type Profile struct {
	ID          primitive.ObjectID `json:"ïd" bson:"_id"`
	AccountID   primitive.ObjectID `bson:"account_id"`
	DisplayName string             `json:"display_name" bson:"display_name" validate:"required"`
	Email       string             `json:"email" bson:"email" validate:"required,email"`
}

//ProfileJSONResponse - to be returned to API client
type ProfileJSONResponse struct {
	ID          string `json:"ïd" bson:"_id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

func (p Profile) ConvertToJSONResponse() ProfileJSONResponse {
	var result ProfileJSONResponse = ProfileJSONResponse{
		ID:          p.ID.Hex(),
		DisplayName: p.DisplayName,
		Email:       p.Email,
	}
	return result
}
