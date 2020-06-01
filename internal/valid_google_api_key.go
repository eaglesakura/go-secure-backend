package internal

import "fmt"

type validGoogleApiKey struct {
	apiKey      string
	serviceName string
}

func (it *validGoogleApiKey) cacheKey() string {
	return fmt.Sprintf("%v:%v", it.serviceName, it.apiKey)
}
