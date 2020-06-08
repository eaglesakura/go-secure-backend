package secure_backend

import (
	"cloud.google.com/go/compute/metadata"
	"context"
	"crypto/rsa"
	"encoding/json"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
	"golang.org/x/xerrors"
	"google.golang.org/api/option"
	"google.golang.org/api/servicecontrol/v1"
	"io/ioutil"
	"net/url"
	"os"
	"time"
)

type securityContextImpl struct {
	ctx    context.Context
	logger *Logger

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
		serviceAccountPublicKeys *googlePublicKeyCache

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

func (it *securityContextImpl) logInfo(message string) {
	it.logger.logInfo(message)
}

func (it *securityContextImpl) NewFirebaseAuthVerifier() FirebaseAuthVerifier {
	return &firebaseAuthVerifierImpl{
		owner:  it,
		logger: it.logger,
	}
}

func (it *securityContextImpl) NewGoogleApiKeyVerifier() GoogleApiKeyVerifier {
	return &googleApiKeyVerifierImpl{
		owner:  it,
		logger: it.logger,
	}
}

func (it *securityContextImpl) getGoogleProjectInfoFromJson(file []byte) (projectId string, email string, publicKey *googlePublicKey, err error) {
	type ServiceAccountModel struct {
		ProjectId    string `json:"project_id"`
		ClientEmail  string `json:"client_email,omitempty"`
		PrivateKeyId string `json:"private_key_id"`
		PrivateKey   string `json:"private_key,omitempty"`
	}

	dto := ServiceAccountModel{}
	if err := json.Unmarshal(file, &dto); err != nil {
		return "", "", nil, xerrors.Errorf("service account parse error %w", err)
	}

	var privateKey *rsa.PrivateKey
	if pem, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(dto.PrivateKey)); err != nil {
		return "", "", nil, xerrors.Errorf("private key parse error %w", err)
	} else {
		privateKey = pem
	}

	return dto.ProjectId, dto.ClientEmail, &googlePublicKey{
		kid:       dto.PrivateKeyId,
		publicKey: &privateKey.PublicKey,
	}, nil
}

func (it *securityContextImpl) getGoogleProjectInfoFromMetadata() (projectId string, serviceAccountEmail string, err error) {
	projectId, err = metadata.ProjectID()
	if err != nil {
		return "", "", xerrors.Errorf("metadata read failed(%v): %w", "ProjectId", err)
	}

	serviceAccountEmail, err = metadata.Get("instance/service-accounts/default/email")
	if err != nil {
		return "", "", xerrors.Errorf("metadata read failed(%v): %w", "instance/service-accounts/default/email", err)
	}

	return projectId, serviceAccountEmail, nil
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

	// init Firebase App.
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
	firebaseAuth, err := firebaseApp.Auth(ctx)
	if err != nil {
		return xerrors.Errorf("Firebase Auth initialize error: %w", err)
	}

	// init ServiceControl.
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

	it.gcp.validApiKeys = cache.New(time.Hour, time.Minute)
	it.gcp.firebaseAuth = firebaseAuth
	it.gcp.serviceAccountJson = serviceAccountJson
	it.gcp.serviceControlClient = serviceCtrl
	if serviceAccountJson != nil {
		it.logInfo("config load from JSON")
		projectId, email, publicKey, err := it.getGoogleProjectInfoFromJson(serviceAccountJson)
		if err != nil {
			return xerrors.Errorf("ServiceAccount file parse failed: %w", err)
		}
		it.logInfo(fmt.Sprintf("GCP initialize success: %v", projectId))
		it.gcp.clientEmail = email
		it.gcp.projectId = projectId
		keyCache := newGooglePublicKeyCache(
			"https://www.googleapis.com/robot/v1/metadata/x509/" + url.PathEscape(email))
		keyCache.addOfflineKey(publicKey)
		err = keyCache.refreshKeys()
		if err != nil {
			return xerrors.Errorf("Public key refresh failed: %w", err)
		}
		it.gcp.serviceAccountPublicKeys = keyCache
	} else {
		it.logInfo("GCP config load from metadata")
		projectId, email, err := it.getGoogleProjectInfoFromMetadata()
		if err != nil {
			return xerrors.Errorf("Metadata parse failed: %w", err)
		}
		it.logInfo(fmt.Sprintf("GCP initialize success: %v", projectId))
		it.gcp.clientEmail = email
		it.gcp.projectId = projectId
		keyCache := newGooglePublicKeyCache(
			"https://www.googleapis.com/robot/v1/metadata/x509/" + url.PathEscape(email))
		err = keyCache.refreshKeys()
		if err != nil {
			return xerrors.Errorf("Public key refresh failed: %w", err)
		}
		it.gcp.serviceAccountPublicKeys = keyCache
	}

	it.logInfo("Google Cloud Platform load completed.")
	it.logInfo(fmt.Sprintf("  * projectId: %v", it.gcp.projectId))
	it.logInfo(fmt.Sprintf("  * service account: %v", it.gcp.clientEmail))
	if it.gcp.serviceAccountPublicKeys.latestKey != nil {
		it.logInfo(fmt.Sprintf("  * public key default: %v", it.gcp.serviceAccountPublicKeys.latestKey.kid))
	}
	for kid, _ := range it.gcp.serviceAccountPublicKeys.allKeys {
		it.logInfo(fmt.Sprintf("  * public key online: %v", kid))
	}

	return nil
}

/*
	Initialize context.
*/
func (it *securityContextImpl) init() error {
	if it.ctx == nil {
		it.ctx = context.Background()
	}
	if it.logger == nil {
		it.logger = &Logger{}
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
		result.logger = configs.Logger
		result.gcp.serviceAccountJson = configs.GoogleServiceAccountJson
	}
	if err := result.init(); err != nil {
		return nil, err
	}
	return result, nil
}
