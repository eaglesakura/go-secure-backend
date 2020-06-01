package secure_backend

import (
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
	"google.golang.org/api/servicecontrol/v1"
	"time"
)

type googleApiKeyVerifierImpl struct {
	owner *securityContextImpl

	/*
		Custom service name.
	*/
	serviceName string
}

func (it *googleApiKeyVerifierImpl) logInfo(msg string) {
	it.owner.logInfo(msg)
}

func (it *googleApiKeyVerifierImpl) logError(msg string) {
	it.owner.logError(msg)
}

func (it *googleApiKeyVerifierImpl) ServiceName(serviceName string) GoogleApiKeyVerifier {
	it.serviceName = serviceName
	return it
}

func (it *googleApiKeyVerifierImpl) verifyImpl(key *validGoogleApiKey) error {
	operationId := uuid.New().String()
	client := it.owner.gcp.serviceControlClient
	resp, err := client.Services.Check(key.serviceName, &servicecontrol.CheckRequest{
		Operation: &servicecontrol.Operation{
			OperationId:   operationId,
			OperationName: "check:" + operationId,
			ConsumerId:    "api_key:" + key.apiKey,
			StartTime:     time.Now().Format(time.RFC3339Nano),
		},
	}).Do()

	if err != nil {
		return xerrors.Errorf("ServiceControl API call failed: %w", err)
	}

	if len(resp.CheckErrors) != 0 {
		var message string
		for i, e := range resp.CheckErrors {
			it.logInfo(fmt.Sprintf("API Key validation error[%v]: %v", i, e.Detail))
			message += fmt.Sprintf("%v,", e.Detail)
		}

		return xerrors.Errorf("API Validation error[%v]", message)
	}

	return nil
}

func (it *googleApiKeyVerifierImpl) Verify(apiKey string) error {
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
		if err := it.verifyImpl(&key); err != nil {
			return err
		}
	} else {
		it.logInfo(fmt.Sprintf("Valid API Key from cache: %v", apiKey))
	}

	// valid API Key.
	validApiKeys.Set(key.cacheKey(), &key, time.Hour)
	return nil
}
