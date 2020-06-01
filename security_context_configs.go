package secure_backend

import (
	"context"
)

/*
	Logger function
*/
type SecurityContextConfigs struct {
	/*
		Custom context.
	*/
	Context context.Context

	/*
		Custom log function.
	*/
	LogInfo func(message string)

	/*
		Custom error log function.
	*/
	LogError func(message string)

	/*
		Custom GCP service account's json file.
		If this value is nil, then load from 'GOOGLE_APPLICATION_CREDENTIALS'.

		see) https://cloud.google.com/docs/authentication/getting-started?hl=en
	*/
	GoogleServiceAccountJson []byte
}
