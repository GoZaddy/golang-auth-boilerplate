package database

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//MongoDBClient is the mongodb client
var (
	mongoDBClient     *mongo.Client
	err               error
	accountCollection *mongo.Collection
	profileCollection *mongo.Collection
	mongodbURI        string
)

func init() {
	godotenv.Load(".env")
}

//Connect connects to MongoDB
func Connect() {

	mongodbURI = os.Getenv("MONGODB_URI")
	clientOptions := options.Client().ApplyURI(mongodbURI)
	mongoDBClient, err = mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}
	accountCollection = mongoDBClient.Database("test").Collection("accounts")
	profileCollection = mongoDBClient.Database("test").Collection("profiles")

	err = mongoDBClient.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connected to mongodb")
}

//Disconnect disconnects from database
func Disconnect() {
	err := mongoDBClient.Disconnect(context.TODO())

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connection to MongoDB closed.")
}
