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

//CreateAccount creates a new account document
func CreateAccount(account models.Account) error {
	var a models.Account
	//oid, _ := primitive.ObjectIDFromHex("5efcb4db9cb4b9bc02cd35e5")
	if account.AuthMethod == models.EMAIL {

		filter := bson.M{
			"auth_method":              "EMAIL",
			"email_auth_details.email": account.EmailAuthDetails.Email,
		}
		result := accountCollection.FindOne(context.Background(), filter)
		result.Decode(&a)
		fmt.Println(a)
		if result.Err() != nil {
			if errors.Is(result.Err(), mongo.ErrNoDocuments) {
				fmt.Println("no documents found")
				_, err := accountCollection.InsertOne(context.Background(), account)
				return err
			}
			return result.Err()
		} else {
			return errors.New("User already exists")
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
func GetAllProfiles() ([]models.Profile, error) {

	var profiles []models.Profile
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

		profiles = append(profiles, profile)
	}
	if err = cur.Err(); err != nil {
		return nil, err
	}

	return profiles, nil
}

//GetProfileWithID returns a profile document with a given id
func GetProfileWithID(id string) (models.Profile, error) {
	var profile models.Profile
	oid, _ := primitive.ObjectIDFromHex(id)
	filter := bson.M{
		"_id": oid,
	}
	result := profileCollection.FindOne(context.Background(), filter)
	if result.Err() != nil {
		return models.Profile{}, result.Err()
	}

	result.Decode(&profile)
	return profile, nil
}

//GetAccountWithEmail gets a specific account by email
func GetAccountWithEmail(email string) (models.Account, error) {
	var account models.Account
	filter := bson.M{
		"auth_method":              models.EMAIL,
		"email_auth_details.email": email,
	}
	result := accountCollection.FindOne(context.Background(), filter)
	if result.Err() != nil {
		return models.Account{}, result.Err()
	}

	result.Decode(&account)
	return account, nil
}
