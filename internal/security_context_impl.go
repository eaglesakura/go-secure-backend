package internal

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/eaglesakura/secure_backend"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2/google"
	"golang.org/x/xerrors"
	"google.golang.org/api/option"
	"google.golang.org/api/servicecontrol/v1"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type securityContextImpl struct {
	ctx      context.Context
	logInfo  func(message string)
	logError func(message string)

	/*
		Google Cloud Platform data.
	*/
	gcp struct {
		/*
			Validated API Keys on memory.
		*/
		validApiKeys *cache.Cache

		serviceAccountJson []byte

		/*
			Private key for Google Cloud Project.
		*/
		privateKey *rsa.PrivateKey

		/*
			Service Account email address.
		*/
		clientEmail string

		/*
			GCP Project ID
		*/
		projectId string

		/*
			Firebase Auth API Client.
		*/
		firebaseAuth *auth.Client

		/*
			Google ServiceControl API client.
		*/
		serviceControlClient *servicecontrol.Service
	}
}

func (it *securityContextImpl) NewFirebaseAuthVerifier() secure_backend.FirebaseAuthVerifier {
	return &firebaseAuthVerifierImpl{
		owner: it,
	}
}

func (it *securityContextImpl) NewGoogleApiKeyVerifier() secure_backend.GoogleApiKeyVerifier {
	return &googleApiKeyVerifierImpl{
		owner: it,
	}
}

func (it *securityContextImpl) initForGcp() error {
	ctx := it.ctx

	serviceAccountJson := it.gcp.serviceAccountJson

	if serviceAccountJson == nil {
		it.logInfo("load Google default credential")
		// load default data
		credentials, _ := google.FindDefaultCredentials(ctx)
		if credentials != nil {
			serviceAccountJson = credentials.JSON
		}
	}

	if serviceAccountJson == nil {
		it.logInfo("load GOOGLE_APPLICATION_CREDENTIALS")

		path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if len(path) == 0 {
			return errors.New("invalid os.Getenv(GOOGLE_APPLICATION_CREDENTIALS)")
		}

		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("service account load failed %w", err)
		}

		serviceAccountJson = bytes
	}

	type ServiceAccountModel struct {
		ProjectId   string `json:"project_id"`
		ClientEmail string `json:"client_email,omitempty"`
		PrivateKey  string `json:"private_key,omitempty"`
	}

	dto := ServiceAccountModel{}
	if err := json.Unmarshal(serviceAccountJson, &dto); err != nil {
		return xerrors.Errorf("service account parse error %w", err)
	}

	var privateKey *rsa.PrivateKey
	if pem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(dto.PrivateKey)); err != nil {
		return xerrors.Errorf("private key parse error %w", err)
	} else {
		privateKey = pem
	}

	var firebaseAuth *auth.Client
	if app, err := firebase.NewApp(ctx, nil, option.WithCredentialsJSON(serviceAccountJson)); err != nil {
		return xerrors.Errorf("Firebase initialize error: %w", err)
	} else if auth, err := app.Auth(ctx); err != nil {
		return xerrors.Errorf("Firebase Auth initialize error: %w", err)
	} else {
		firebaseAuth = auth
	}

	var serviceControlClient *servicecontrol.Service
	if client, err := servicecontrol.NewService(ctx, option.WithCredentialsJSON(serviceAccountJson)); err != nil {
		return xerrors.Errorf("ServiceControl client error: %w", err)
	} else {
		serviceControlClient = client
	}

	it.logInfo(fmt.Sprintf("GCP initialize success: %v", dto.ProjectId))
	it.gcp.validApiKeys = cache.New(time.Hour, time.Minute)
	it.gcp.firebaseAuth = firebaseAuth
	it.gcp.serviceAccountJson = serviceAccountJson
	it.gcp.privateKey = privateKey
	it.gcp.clientEmail = dto.ClientEmail
	it.gcp.projectId = dto.ProjectId
	it.gcp.serviceControlClient = serviceControlClient

	return nil
}

/*
	Initialize context.
*/
func (it *securityContextImpl) init() error {
	if it.ctx == nil {
		it.ctx = context.Background()
	}

	if it.logInfo == nil {
		it.logInfo = func(message string) {
			log.Println(message)
		}
	}
	if it.logError == nil {
		it.logError = func(message string) {
			log.Println(message)
		}
	}

	if err := it.initForGcp(); err != nil {
		return err
	}
	return nil
}

/*
	New instance.
*/
func NewSecurityContext(configs *secure_backend.SecurityContextConfigs) (secure_backend.SecurityContext, error) {
	result := &securityContextImpl{}
	if configs != nil {
		result.ctx = configs.Context
		result.logInfo = configs.LogInfo
		result.logError = configs.LogError
		result.gcp.serviceAccountJson = configs.GoogleServiceAccountJson
	}
	if err := result.init(); err != nil {
		return nil, err
	}
	return result, nil
}
