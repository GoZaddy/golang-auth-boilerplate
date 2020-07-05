package database

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/go-playground/validator.v9"

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

func CreateAccountWithEmailDetails(email string, password []byte, name string) (string, error) {
	var accountFromDB models.Account
	var validate *validator.Validate = validator.New()

	filter := bson.M{
		"email": email,
	}
	result := accountCollection.FindOne(context.Background(), filter)
	result.Decode(&accountFromDB)
	if result.Err() != nil {
		if errors.Is(result.Err(), mongo.ErrNoDocuments) {
			fmt.Println("no documents found")
			accountID := primitive.NewObjectID()
			profileID := primitive.NewObjectID()

			newAccount := models.Account{
				ID:            accountID,
				Email:         email,
				AuthProviders: []string{models.EMAIL},
				EmailAuthDetails: &models.EmailAuth{
					Password: password,
				},
				ProfileID: profileID,
			}

			newProfile := models.Profile{
				ID:          profileID,
				AccountID:   accountID,
				DisplayName: name,
				Email:       email,
			}

			err := validate.Struct(newAccount)
			if err != nil {
				return "", err
			}
			_, err = accountCollection.InsertOne(context.Background(), newAccount)
			if err != nil {
				return "", err
			}
			err = validate.Struct(newProfile)
			if err != nil {
				return "", err
			}
			err = CreateProfile(newProfile)
			if err != nil {
				return "", err
			}
			return profileID.Hex(), nil
		}
		return "", result.Err()
	}
	//check if the email auth details of this account is empty(no email auth details) and if email provider is not among the providers. If those two are true, update the account to include email auth

	if accountFromDB.EmailAuthDetails == nil && indexOf(accountFromDB.AuthProviders, models.EMAIL) == -1 {
		filter = bson.M{
			"_id": accountFromDB.ID,
		}
		update := bson.M{
			"$set": bson.M{
				"email_auth_details": &models.EmailAuth{
					Password: password,
				},
			},
			"$addToSet": bson.M{
				"auth_providers": models.EMAIL,
			},
		}

		_, err := accountCollection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			return "", err
		}
		return accountFromDB.ProfileID.Hex(), nil
	} else {
		return "", errors.New("User already exists")
	}

}

func CreateAccountWithOauthDetails(oauthDetails models.OAuthUserDetails) (string, error) {
	var accountFromDB models.Account
	var validate *validator.Validate = validator.New()
	authProvider := oauthDetails.GetAuthProvider()
	email := oauthDetails.GetEmail()

	filter := bson.M{
		"email": email,
	}
	result := accountCollection.FindOne(context.Background(), filter)
	result.Decode(&accountFromDB)
	if result.Err() != nil {
		if errors.Is(result.Err(), mongo.ErrNoDocuments) {
			fmt.Println("no documents found")
			accountID := primitive.NewObjectID()
			profileID := primitive.NewObjectID()
			var newAccount models.Account
			newAccount = models.Account{
				ID:            accountID,
				AuthProviders: []string{authProvider},
				ProfileID:     profileID,
				Email:         email,
			}

			newProfile := models.Profile{
				ID:          profileID,
				AccountID:   accountID,
				Email:       email,
				DisplayName: oauthDetails.GetUserName(),
			}

			switch authProvider {
			case models.GITHUB:
				newAccount.GithubAuthDetails = &models.GithubAuth{
					ID: oauthDetails.GetID(),
				}
			case models.GOOGLE:
				newAccount.GoogleAuthDetails = &models.GoogleAuth{
					ID: oauthDetails.GetID(),
				}
			}
			err := validate.Struct(newAccount)
			if err != nil {
				return "", err
			}
			_, err = accountCollection.InsertOne(context.Background(), newAccount)
			if err != nil {
				return "", err
			}
			err = validate.Struct(newProfile)
			if err != nil {
				return "", err
			}
			err = CreateProfile(newProfile)
			if err != nil {
				return "", err
			}
			return profileID.Hex(), nil
		}
		return "", result.Err()
	}
	//check if the email auth details of this account is empty(no email auth details) and if email provider is not among the providers. If those two are true, update the account to include email auth
	filter = bson.M{
		"_id": accountFromDB.ID,
	}
	var update bson.M
	addToSet := bson.M{
		"auth_providers": authProvider,
	}
	switch authProvider {
	case models.GOOGLE:
		if accountFromDB.GoogleAuthDetails == nil && indexOf(accountFromDB.AuthProviders, models.GOOGLE) == -1 {
			update = bson.M{
				"$set": bson.M{
					"google_auth_details": &models.GoogleAuth{
						ID: oauthDetails.GetID(),
					},
				},
				"$addToSet": addToSet,
			}
			_, err := accountCollection.UpdateOne(context.Background(), filter, update)
			if err != nil {
				return "", err
			}
			return accountFromDB.ProfileID.Hex(), nil
		} else if accountFromDB.GoogleAuthDetails.ID == oauthDetails.GetID() {
			return accountFromDB.ProfileID.Hex(), nil
		}
	case models.GITHUB:
		if accountFromDB.GithubAuthDetails == nil && indexOf(accountFromDB.AuthProviders, models.GITHUB) == -1 {
			update = bson.M{
				"$set": bson.M{
					"github_auth_details": &models.GithubAuth{
						ID: oauthDetails.GetID(),
					},
				},
				"$addToSet": addToSet,
			}
			_, err := accountCollection.UpdateOne(context.Background(), filter, update)
			if err != nil {
				return "", err
			}
			return accountFromDB.ProfileID.Hex(), nil
		} else if accountFromDB.GithubAuthDetails.ID == oauthDetails.GetID() {
			return accountFromDB.ProfileID.Hex(), nil
		}
	}
	return "", nil
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
