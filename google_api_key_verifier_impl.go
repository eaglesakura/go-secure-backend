package secure_backend

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/api/servicecontrol/v1"
)

type googleApiKeyVerifierImpl struct {
	owner *securityContextImpl

	logger *Logger

	/*
		Custom service name.
	*/
	serviceName string
}

func (it *googleApiKeyVerifierImpl) logInfo(msg string) {
	it.logger.logInfo(msg)
}

func (it *googleApiKeyVerifierImpl) logError(msg string) {
	it.logger.logError(msg)
}

func (it *googleApiKeyVerifierImpl) SetLogger(logger *Logger) {
	it.logger = logger
}

func (it *googleApiKeyVerifierImpl) SetServiceName(serviceName string) {
	it.serviceName = serviceName
}

func (it *googleApiKeyVerifierImpl) verifyImpl(ctx context.Context, key *validGoogleApiKey) error {
	operationId := uuid.New().String()
	client := it.owner.gcp.serviceControlClient
	resp, err := client.Services.Check(key.serviceName, &servicecontrol.CheckRequest{
		Operation: &servicecontrol.Operation{
			OperationId:   operationId,
			OperationName: "check:" + operationId,
			ConsumerId:    "api_key:" + key.apiKey,
			StartTime:     time.Now().Format(time.RFC3339Nano),
		},
	}).Context(ctx).Do()

	if err != nil {
		return fmt.Errorf("ServiceControl API call failed: %w", err)
	}

	if len(resp.CheckErrors) != 0 {
		var message string
		for i, e := range resp.CheckErrors {
			it.logInfo(fmt.Sprintf("API Key validation error[%v]: %v", i, e.Detail))
			message += fmt.Sprintf("%v,", e.Detail)
		}

		return fmt.Errorf("API Validation error[%v]", message)
	}

	return nil
}

func (it *googleApiKeyVerifierImpl) Verify(ctx context.Context, apiKey string) error {
	// check cache
	validApiKeys := it.owner.gcp.validApiKeys

	key := validGoogleApiKey{
		apiKey:      apiKey,
		serviceName: it.serviceName,
	}

	if len(key.serviceName) == 0 {
		key.serviceName = fmt.Sprintf("%v.appspot.com", it.owner.gcp.projectId)
	}

	if _, ok := validApiKeys.Get(key.cacheKey()); !ok {
		// cache not found.
		// do check this API Key.
		it.logInfo(fmt.Sprintf("Validation API Key by ServiceControl API: %v:hash(%v)", key.serviceName, sha512sum(key.apiKey)))
		if err := it.verifyImpl(ctx, &key); err != nil {
			return err
		}
	} else {
		it.logInfo(fmt.Sprintf("Valid API Key from cache: %v", apiKey))
	}

	// valid API Key.
	validApiKeys.Set(key.cacheKey(), &key, time.Hour)
	return nil
}
