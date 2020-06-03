package secure_backend

import (
	"context"
	"errors"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
	"golang.org/x/xerrors"
	"google.golang.org/api/option"
	"google.golang.org/api/servicecontrol/v1"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"
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
			Current public Key
		*/
		serviceAccountPublicKey *googlePublicKey

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

func (it *securityContextImpl) NewFirebaseAuthVerifier() FirebaseAuthVerifier {
	return &firebaseAuthVerifierImpl{
		owner: it,
	}
}

func (it *securityContextImpl) NewGoogleApiKeyVerifier() GoogleApiKeyVerifier {
	return &googleApiKeyVerifierImpl{
		owner: it,
	}
}

func (it *securityContextImpl) findPublicKey(ctx context.Context, client *auth.Client, serviceAccountEmail string) (*googlePublicKey, error) {
	keys, err := getGooglePublicKeys("https://www.googleapis.com/robot/v1/metadata/x509/" + url.PathEscape(serviceAccountEmail))
	if err != nil {
		return nil, err
	}

	token, _ := client.CustomToken(ctx, "dummy-user-id")
	// try all key
	for _, key := range keys {
		_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return key.publicKey, nil
		})
		if err == nil {
			it.logInfo(fmt.Sprintf("Google Public KID: %v", key.kid))
			return key, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Public key not found: %v", serviceAccountEmail))
}

func (it *securityContextImpl) getGoogleProjectInfo(ctx context.Context, client *auth.Client) (projectId string, serviceAccountEmail string, publicKey *googlePublicKey, err error) {
	token, err := client.CustomToken(ctx, "dummy-user-id")
	if err != nil {
		return "", "", nil, xerrors.Errorf("Mock token generate failed: %w", err)
	}

	parse, _ := jwt.Parse(token, nil)
	claims := parse.Claims.(jwt.MapClaims)

	serviceAccountEmail = claims["iss"].(string)
	projectId = serviceAccountEmail[strings.Index(serviceAccountEmail, "@")+1 : strings.Index(serviceAccountEmail, ".iam.gserviceaccount.com")]

	// download public key.
	publicKey, err = it.findPublicKey(ctx, client, serviceAccountEmail)
	if err != nil {
		return "", "", nil, err
	}

	return projectId, serviceAccountEmail, publicKey, nil
}

func (it *securityContextImpl) initForGcp() error {
	ctx := it.ctx

	serviceAccountJson := it.gcp.serviceAccountJson
	if serviceAccountJson == nil {
		it.logInfo("load GOOGLE_APPLICATION_CREDENTIALS")

		path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		if len(path) > 0 {
			bytes, err := ioutil.ReadFile(path)
			if err != nil {
				return xerrors.Errorf("service account load failed %w", err)
			}
			serviceAccountJson = bytes
		}
	}

	if len(serviceAccountJson) > 0 {
		it.logInfo("Init service account from JSON key")
	} else {
		it.logInfo("Init service account from System key")
	}

	firebaseApp, err := func() (*firebase.App, error) {
		if len(serviceAccountJson) > 0 {
			return firebase.NewApp(ctx, nil, option.WithCredentialsJSON(serviceAccountJson))
		} else {
			return firebase.NewApp(ctx, nil)
		}
	}()
	if err != nil {
		return xerrors.Errorf("Firebase App init failed: %w", err)
	}
	serviceCtrl, err := func() (*servicecontrol.Service, error) {
		if len(serviceAccountJson) > 0 {
			return servicecontrol.NewService(ctx, option.WithCredentialsJSON(serviceAccountJson))
		} else {
			return servicecontrol.NewService(ctx)
		}
	}()

	if err != nil {
		return xerrors.Errorf("ServiceControl init failed: %w", err)
	}

	firebaseAuth, err := firebaseApp.Auth(ctx)
	if err != nil {
		return xerrors.Errorf("Firebase Auth initialize error: %w", err)
	}

	projectId, email, publicKey, err := it.getGoogleProjectInfo(ctx, firebaseAuth)
	if err != nil {
		return xerrors.Errorf("parse project info failed: %w", err)
	}

	it.logInfo(fmt.Sprintf("GCP initialize success: %v", projectId))
	it.gcp.validApiKeys = cache.New(time.Hour, time.Minute)
	it.gcp.serviceAccountPublicKey = publicKey
	it.gcp.firebaseAuth = firebaseAuth
	it.gcp.serviceAccountJson = serviceAccountJson
	it.gcp.clientEmail = email
	it.gcp.projectId = projectId
	it.gcp.serviceControlClient = serviceCtrl

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
func NewSecurityContext(configs *SecurityContextConfigs) (SecurityContext, error) {
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
