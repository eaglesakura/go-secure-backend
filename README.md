# go-secure-backend

# Firebase Auth token verifier

```go
var securityContext SecurityContext

func HandleHttp(w http.ResponseWriter, r *http.Request) {
    authToken := // get Firebase Token from request.

    parsedToken, err := securityContext.NewFirebaseAuthVerifier().Verify(apiKey)
    if err != nil {
        panic("Invalid Firebase Token!!")
    }
    
    // do something...
}

func main() {
    configs := &secure_backend.SecurityContextConfigs{}
    if ctx, err := secure_backend.NewSecurityContext(configs); err != nil {
        panic(err)
    } else {
        securityContext = ctx
    }
}
```

# Google Cloud Platform API Key validator

Validation your API Key, created by Google Cloud Platform.

```go

var securityContext SecurityContext

func HandleHttp(w http.ResponseWriter, r *http.Request) {
    apiKey := // get Google API Key from reqeust.
    if !securityContext.NewGoogleApiKeyVerifier().Verify(apiKey) {
        panic("Invalid Google API Key!!")
    }
    
    // do something.
}

func main() {
    configs := &secure_backend.SecurityContextConfigs{}
    if ctx, err := secure_backend.NewSecurityContext(configs); err != nil {
        panic(err)
    } else {
        securityContext = ctx
    }
}
```

## Step1. Enable ServiceControl API.

You need [ServiceControl](https://console.cloud.google.com/apis/library/servicecontrol.googleapis.com) API to enable.

## Step2. Deploy Swagger file to Cloud Endpoint.

Deploy your API spec to Cloud Endpoint.

If you not use OpenAPI Based API,
then you can deploy mock file to Endpoint.

```bash
# Init your GCP project.
gcloud init

# deploy
cd path/to/go-secure-backend
./scripts/enable-cloud-endpoint.sh "your-gcp-project-name.appspot.com"
```
## Step3. IAM settings.

You need attach 'servicemanagement.services.check' permission to your service account.
example, you can attach 'Service Controller' role to your Service Account.

## (Option) Step4. API Key security.

You can enable 'restrict key' mode to your API Key on GCP Console.

Go to "GCP Console > APIs & Services > Credentials > (API Key) > API restrictions > Your serviceName"
e.g.) "your-gcp-project.appspot.com" API.

