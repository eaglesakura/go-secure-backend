package secure_backend

/*
logger function
*/
type SecurityContextConfigs struct {
	/*
		Custom logger.
	*/
	Logger *Logger

	/*
		Custom GCP service account's json file.
		If this value is nil, then load from 'GOOGLE_APPLICATION_CREDENTIALS'.

		see) https://cloud.google.com/docs/authentication/getting-started?hl=en
	*/
	GoogleServiceAccountJson []byte
}
