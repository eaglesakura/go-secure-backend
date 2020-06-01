package secure_backend

/*
Google Cloud Platform API Key verify.
*/
type GoogleApiKeyVerifier interface {
	/*
		Set custom service name for 'Service Control' check API.
		Default is 'your-gcp-name.appspot.com'
		https://cloud.google.com/service-infrastructure/docs/service-control/getting-started?hl=en
	*/
	ServiceName(serviceName string) GoogleApiKeyVerifier

	/*
		Verify your API Key.
	*/
	Verify(apiKey string) error
}
