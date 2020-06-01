package secure_backend

import (
	"context"
)

/*
	Logger function
*/
type SecurityContextConfigs struct {
	Context  context.Context
	LogInfo  func(message string)
	LogError func(message string)

	/*
		GCP service account's json file.
		If this value is nil, then load from 'GOOGLE_APPLICATION_CREDENTIALS'.

		see) https://cloud.google.com/docs/authentication/getting-started?hl=en
	*/
	GoogleServiceAccountJson []byte
}
