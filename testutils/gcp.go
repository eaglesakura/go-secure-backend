package testutils

import (
	"context"
	"errors"
	"golang.org/x/oauth2/google"
	"os"
)

func GetGoogleApiKeyForTest() string {
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if len(apiKey) == 0 {
		panic(errors.New("invalid os.Getenv(GOOGLE_API_KEY)"))
	}

	return apiKey
}

func GetGoogleCredentialForTest(ctx context.Context) *google.Credentials {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		panic(err)
	}
	return credentials
}
