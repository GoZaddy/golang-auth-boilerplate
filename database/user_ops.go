package database

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/gozaddy/golang-auth-boilerplate/models"

	"go.mongodb.org/mongo-driver/bson"
)

func indexOf(s []string, input string) int {
	for index, value := range s {
		if value == input {
			return index
		}
	}
	return -1
}

//CreateAccount creates a new account document. For the  auth methods, add only the auth provider you are currently creating an account with
func CreateAccount(account models.Account) error {
	var accountFromDB models.Account

	switch account.AuthProviders[0] {
	case models.EMAIL:
		filter := bson.M{
			"email": account.Email,
		}
		result := accountCollection.FindOne(context.Background(), filter)
		result.Decode(&accountFromDB)
		if result.Err() != nil {
			if errors.Is(result.Err(), mongo.ErrNoDocuments) {
				fmt.Println("no documents found")
				_, err := accountCollection.InsertOne(context.Background(), account)
				return err
			}
			return result.Err()
		} else {
			//check if the email auth details of this account is empty(no email auth details) and if email provider is not among the providers. If those two are true, update the account to include email auth

			if accountFromDB.EmailAuthDetails == nil && indexOf(accountFromDB.AuthProviders, models.EMAIL) == -1 {
				filter = bson.M{
					"_id": accountFromDB.ID,
				}
				update := bson.M{
					"email_auth_details": account.EmailAuthDetails,
					"$addToSet": bson.M{
						"auth_providers": models.EMAIL,
					},
				}

				_, err := accountCollection.UpdateOne(context.Background(), filter, update)
				return err
			} else {
				return errors.New("User already exists")
			}
		}
	case models.GOOGLE:
		filter := bson.M{
			"email": account.Email,
		}
		result := accountCollection.FindOne(context.Background(), filter)
		result.Decode(&accountFromDB)
		if result.Err() != nil {
			if errors.Is(result.Err(), mongo.ErrNoDocuments) {
				fmt.Println("no documents found")
				_, err := accountCollection.InsertOne(context.Background(), account)
				return err
			}
			return result.Err()
		} else {
			//check if the email auth details of this account is empty(no email auth details) and if email provider is not among the providers. If those two are true, update the account to include email auth

			if accountFromDB.GoogleAuthDetails == nil && indexOf(accountFromDB.AuthProviders, models.GOOGLE) == -1 {
				filter = bson.M{
					"_id": accountFromDB.ID,
				}
				update := bson.M{
					"google_auth_details": account.GoogleAuthDetails,
					"$addToSet": bson.M{
						"auth_providers": models.GOOGLE,
					},
				}

				_, err := accountCollection.UpdateOne(context.Background(), filter, update)
				return err
			} else if accountFromDB.GoogleAuthDetails.ID == accountFromDB.GoogleAuthDetails.ID {
				return errors.New("User already exists")
			} else {
				//TODO
				errors.New("ERROR ERROR ERROR!")
			}
		}

	}

	return nil

}

//CreateProfile creates a new profile document
func CreateProfile(profile models.Profile) error {
	_, err := profileCollection.InsertOne(context.Background(), profile)
	return err
}

//GetAllProfiles gets all users documents from the db
func GetAllProfiles() ([]models.ProfileJSONResponse, error) {

	var profiles []models.ProfileJSONResponse
	cur, err := profileCollection.Find(context.Background(), bson.D{}, nil)
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var profile models.Profile

		err = cur.Decode(&profile)
		if err != nil {
			return nil, err
		}

		profiles = append(profiles, profile.ConvertToJSONResponse())
	}
	if err = cur.Err(); err != nil {
		return nil, err
	}

	return profiles, nil
}

//GetProfileWithID returns a profile document with a given id
func GetProfileWithID(id string) (models.ProfileJSONResponse, error) {
	var profile models.Profile
	oid, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{
		"_id": oid,
	}
	result := profileCollection.FindOne(context.Background(), filter)
	if result.Err() != nil {
		return models.ProfileJSONResponse{}, result.Err()
	}

	result.Decode(&profile)
	return profile.ConvertToJSONResponse(), nil
}

//GetAccountWithEmail gets a specific account(registered with email) by email
func GetAccountWithEmail(email string) (models.Account, error) {
	var account models.Account
	filter := bson.M{
		"auth_providers": models.EMAIL,
		"email":          email,
		"email_auth_details.password": bson.M{
			"$exists": true,
		},
	}
	result := accountCollection.FindOne(context.Background(), filter)
	if result.Err() != nil {
		return models.Account{}, result.Err()
	}

	result.Decode(&account)
	return account, nil
}

//GetAccountWithGoogleSub gets a specific account(registered with google) by the sub field provided by google during oauth
func GetAccountWithGoogleSub(sub string) (models.Account, error) {
	var account models.Account
	filter := bson.M{
		"auth_providers":         models.GOOGLE,
		"google_auth_details.id": sub,
	}

	result := accountCollection.FindOne(context.Background(), filter)
	if result.Err() != nil {
		return models.Account{}, result.Err()
	}

	result.Decode(&account)
	return account, nil
}
