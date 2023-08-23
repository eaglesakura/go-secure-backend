package secure_backend

import "context"

/*
Google Cloud Platform API Key verify.
*/
type GoogleApiKeyVerifier interface {
	// Set custom logger.
	SetLogger(logger *Logger)

	// Set custom service name for 'Service Control' check API.
	// Default is 'your-gcp-name.appspot.com'
	// https://cloud.google.com/service-infrastructure/docs/service-control/getting-started?hl=en
	SetServiceName(serviceName string)

	// Verify your API Key.
	Verify(ctx context.Context, apiKey string) error
}
