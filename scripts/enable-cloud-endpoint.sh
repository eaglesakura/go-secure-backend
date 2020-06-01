#! /bin/bash -eu

# example.
# $ ./scripts/enable-cloud-endpoint.sh "your-gcp-project-name.appspot.com"

cat scripts/openapi.template.yaml \
  | sed "s/HOST_NAME/$1/g" \
  > ./openapi.yaml
gcloud endpoints services deploy openapi.yaml
rm ./openapi.yaml
