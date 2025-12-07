// database/firebase.go
package database

import (
	"context"
	"os"

	firebase "firebase.google.com/go/v4"
	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

// InitFirebase initializes Firebase client
func InitFirebase(ctx context.Context) (*firestore.Client, error) {
	// Get credentials path from environment
	credPath := os.Getenv("FIREBASE_CREDENTIALS_PATH")
	if credPath == "" {
		credPath = "./serviceAccountKey.json"
	}

	// Initialize Firebase app
	opt := option.WithCredentialsFile(credPath)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, err
	}

	// Initialize Firestore client
	client, err := app.Firestore(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
}