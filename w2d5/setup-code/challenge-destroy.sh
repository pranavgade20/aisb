#!/bin/bash

FIRST_SCRIPT_ARG="$1"

# Global variables for cleanup - will be set later
PROJECT_ID=""
PROJECT_NUMBER=""
REGION=""

# Define directory structure - matching challenge-setup.sh
THIS_DIR="$(realpath .)"
ANSWER_DIR="${THIS_DIR}/.answerfiles-dontreadpls-spoilers-sadge"
TEMPFILE_DIR="${ANSWER_DIR}/temporary_files"
TFMAIN_DIR="${ANSWER_DIR}/terraform"
TFMOD1_DIR="${ANSWER_DIR}/terraform_module1"
TFMOD2_DIR="${ANSWER_DIR}/terraform_module2"

# Function to check terraform state
check_terraform_state() {
    local dir=$1
    if [ -f "$dir/terraform.tfstate" ]; then
        local resource_count=$(terraform -chdir="$dir" state list 2>/dev/null | grep -c "google_" || echo "0")
        echo "Found $resource_count managed resources in $dir state"
        return 0
    fi
    echo "No state file found in $dir"
    return 1
}

# Helper function to check if a resource is already in terraform state
is_resource_in_state() {
    local resource_address=$1
    terraform state list 2>/dev/null | grep -q "^${resource_address}$"
    return $?
}

# Function to detect and report zombie resources
detect_zombie_resources() {
    echo "##########################################################"
    echo "> Detecting zombie/orphaned resources..."
    echo "##########################################################"
    
    local has_zombies=false
    
    # Check for UNKNOWN state functions
    local zombie_funcs=$(gcloud functions list --filter="state:UNKNOWN" --format="value(name)" 2>/dev/null)
    if [ ! -z "$zombie_funcs" ]; then
        echo "WARNING: Found zombie cloud functions:"
        echo "$zombie_funcs"
        has_zombies=true
    fi
    
    # Check for orphaned Cloud Run services without functions
    local orphan_runs=$(gcloud run services list --format="value(name)" 2>/dev/null | \
        while read service; do
            if ! gcloud functions list --format="value(name)" 2>/dev/null | grep -q "^$service$"; then
                echo "$service"
            fi
        done)
    
    if [ ! -z "$orphan_runs" ]; then
        echo "WARNING: Found orphaned Cloud Run services:"
        echo "$orphan_runs"
        has_zombies=true
    fi
    
    if [ "$has_zombies" = true ]; then
        echo ""
        echo "These resources will be forcefully cleaned up."
    else
        echo "No zombie resources detected."
    fi
    
    return 0
}


# Cleanup function that ensures ALL resources are deleted
cleanup_all_gcp_resources() {
    echo "##########################################################"
    echo "> Performing COMPREHENSIVE GCP resource cleanup..."
    echo "##########################################################"
    
    # Ensure we're not using student-workshop before cleanup
    CURRENT_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
    if [[ "$CURRENT_ACCOUNT" == *"student-workshop"* ]]; then
        echo "WARNING: Still using student-workshop account, forcing switch..."
        
        # Always use default configuration (admin-backup gets deleted later anyway)
        echo "Switching to default configuration..."
        gcloud config configurations activate default
        
        DEFAULT_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
        if [ ! -z "$DEFAULT_ACCOUNT" ]; then
            echo "Setting active account to: $DEFAULT_ACCOUNT"
            gcloud config set account "$DEFAULT_ACCOUNT" 2>/dev/null
            ADMIN_ACCOUNT="$DEFAULT_ACCOUNT"
        else
            echo "ERROR: No account in default configuration"
            echo "Please run: gcloud auth login"
            exit 1
        fi
        
        # Verify the switch worked
        CURRENT_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
        if [[ "$CURRENT_ACCOUNT" == *"student-workshop"* ]]; then
            echo "ERROR: Failed to switch away from student-workshop account"
            exit 1
        fi
    fi
    
    # Force use admin account for cleanup operations if set
    if [ ! -z "$ADMIN_ACCOUNT" ]; then
        export CLOUDSDK_CORE_ACCOUNT="${ADMIN_ACCOUNT}"
    fi
    
    # PHASE 1: Delete Cloud Functions v2 (must be before Cloud Run)
    echo "=== PHASE 1: Cleaning up ALL Cloud Functions v2 ==="
    
    # Explicitly delete cloudai-portal function
    for region in us-east1 us-central1 us-west1; do
        if gcloud functions describe cloudai-portal --region="$region" --project="$PROJECT_ID" &>/dev/null; then
            echo "  Found cloudai-portal in $region - deleting..."
            gcloud functions delete cloudai-portal \
                --region="$region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # Explicitly delete monitoring-function
    for region in us-east1 us-central1 us-west1; do
        if gcloud functions describe monitoring-function --region="$region" --project="$PROJECT_ID" &>/dev/null; then
            echo "  Found monitoring-function in $region - deleting..."
            gcloud functions delete monitoring-function \
                --region="$region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # Delete ALL remaining functions (any region, any state)
    for func in $(gcloud functions list --format="value(name)" --project="$PROJECT_ID" 2>/dev/null); do
        func_region=$(gcloud functions list --filter="name:$func" --format="value(location)" --project="$PROJECT_ID" 2>/dev/null)
        if [ ! -z "$func_region" ]; then
            echo "  Deleting function $func in region $func_region..."
            gcloud functions delete "$func" \
                --region="$func_region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # PHASE 2: Delete orphaned Cloud Run services (AFTER functions)
    echo "=== PHASE 2: Cleaning up orphaned Cloud Run services ==="
    for service in $(gcloud run services list --format="value(name)" --project="$PROJECT_ID" 2>/dev/null); do
        service_region=$(gcloud run services list --filter="name:$service" --format="value(region)" --project="$PROJECT_ID" 2>/dev/null)
        if [ ! -z "$service_region" ]; then
            echo "  Deleting Cloud Run service $service in region $service_region..."
            gcloud run services delete "$service" \
                --region="$service_region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # PHASE 3: Delete compute instances
    echo "=== PHASE 3: Cleaning up compute instances ==="
    for instance in $(gcloud compute instances list --format="value(name)" --project="$PROJECT_ID" 2>/dev/null); do
        zone=$(gcloud compute instances list --filter="name:$instance" --format="value(zone)" --project="$PROJECT_ID" 2>/dev/null)
        if [ ! -z "$zone" ]; then
            echo "  Deleting instance $instance in zone $zone..."
            gcloud compute instances delete "$instance" \
                --zone="$zone" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # PHASE 4: Delete ALL storage buckets
    echo "=== PHASE 4: Cleaning up ALL storage buckets ==="
    for bucket in $(gcloud storage buckets list --format="value(name)" --project="$PROJECT_ID" 2>/dev/null | grep -E "modeldata-|file-uploads-|cloud-function-bucket-" || true); do
        echo "  Deleting bucket gs://$bucket..."
        gcloud storage rm -r "gs://$bucket/" --project="$PROJECT_ID" 2>/dev/null || true
    done
    
    # PHASE 5: Delete ALL secrets
    echo "=== PHASE 5: Cleaning up secrets ==="
    for secret in $(gcloud secrets list --format="value(name)" --project="$PROJECT_ID" 2>/dev/null | grep -E "ssh-key" || true); do
        echo "  Deleting secret $secret..."
        gcloud secrets delete "$secret" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    done
    
    # PHASE 6: Delete service accounts
    echo "=== PHASE 6: Cleaning up service accounts ==="
    for sa in bucket-service-account monitoring-function terraform-pipeline cloudai-portal student-workshop; do
        if gcloud iam service-accounts describe "$sa@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
            echo "  Deleting service account $sa..."
            gcloud iam service-accounts delete \
                "$sa@$PROJECT_ID.iam.gserviceaccount.com" \
                --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # PHASE 7: Delete custom IAM roles
    echo "=== PHASE 7: Cleaning up custom IAM roles ==="
    for role in DevBucketAccess TerraformPipelineProjectAdmin; do
        if gcloud iam roles describe "$role" --project="$PROJECT_ID" &>/dev/null; then
            echo "  Deleting custom role $role..."
            gcloud iam roles delete "$role" --project="$PROJECT_ID" --quiet 2>/dev/null || true
        fi
    done
    
    # PHASE 8: Clean up IAM policy bindings
    echo "=== PHASE 8: Cleaning up IAM bindings ==="
    # Remove specific bindings for deleted service accounts
    for sa in bucket-service-account monitoring-function terraform-pipeline student-workshop; do
        member="serviceAccount:$sa@$PROJECT_ID.iam.gserviceaccount.com"
        # Get all roles for this member
        roles=$(gcloud projects get-iam-policy "$PROJECT_ID" --format="json" | \
            python3 -c "import sys, json; policy = json.load(sys.stdin); [print(b['role']) for b in policy.get('bindings', []) if 'serviceAccount:$sa@$PROJECT_ID.iam.gserviceaccount.com' in b.get('members', [])]" 2>/dev/null || true)
        for role in $roles; do
            if [ ! -z "$role" ]; then
                echo "  Removing $member from role $role..."
                gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
                    --member="$member" --role="$role" 2>/dev/null || true
            fi
        done
    done
    
    echo "Comprehensive cleanup complete!"
}

# Import function for module2 resources
import_module2_resources() {
    echo "Attempting to import module2 resources into state..."
    
    # Check if instance exists and import (only if not already in state)
    if gcloud compute instances describe app-prod-instance-module2 \
        --zone=us-east1-b --project="$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_compute_instance.compute-instance-module2"; then
            echo "  Importing compute instance..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_compute_instance.compute-instance-module2 \
                "projects/$PROJECT_ID/zones/us-east1-b/instances/app-prod-instance-module2" \
                2>/dev/null || true
        else
            echo "  Compute instance already in state, skipping import"
        fi
    fi
    
    # Check if bucket exists and import (only if not already in state)
    if gcloud storage buckets describe "gs://file-uploads-$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_storage_bucket.bucket-module2"; then
            echo "  Importing storage bucket..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_storage_bucket.bucket-module2 \
                "file-uploads-$PROJECT_ID" 2>/dev/null || true
        else
            echo "  Storage bucket already in state, skipping import"
        fi
    fi
    
    # Check if secret exists and import (only if not already in state)
    if gcloud secrets describe ssh-key --project="$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_secret_manager_secret.ssh-secret-module2"; then
            echo "  Importing secret..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_secret_manager_secret.ssh-secret-module2 \
                "projects/$PROJECT_ID/secrets/ssh-key" 2>/dev/null || true
        else
            echo "  Secret already in state, skipping import"
        fi
    fi
}

# Import function for main terraform directory resources
import_terraform_resources() {
    echo "Attempting to import main terraform resources into state..."
    
    # Module 1 resources
    # Check if bucket-service-account exists and import (only if not already in state)
    if gcloud iam service-accounts describe "bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
        if ! is_resource_in_state "google_service_account.bucket-service-account"; then
            echo "  Importing bucket-service-account..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_service_account.bucket-service-account \
                "projects/$PROJECT_ID/serviceAccounts/bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" \
                2>/dev/null || true
        else
            echo "  bucket-service-account already in state, skipping import"
        fi
    fi
    
    # Check if DevBucketAccess role exists and import (only if not already in state)
    if gcloud iam roles describe DevBucketAccess --project="$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_project_iam_custom_role.dev-bucket-access"; then
            echo "  Importing DevBucketAccess role..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_project_iam_custom_role.dev-bucket-access \
                "projects/$PROJECT_ID/roles/DevBucketAccess" \
                2>/dev/null || true
        else
            echo "  DevBucketAccess role already in state, skipping import"
        fi
    fi
    
    # Check if modeldata buckets exist and import (only if not already in state)
    if gcloud storage buckets describe "gs://modeldata-dev-$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_storage_bucket.modeldata-dev"; then
            echo "  Importing modeldata-dev bucket..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_storage_bucket.modeldata-dev \
                "modeldata-dev-$PROJECT_ID" 2>/dev/null || true
        else
            echo "  modeldata-dev bucket already in state, skipping import"
        fi
    fi
    
    if gcloud storage buckets describe "gs://modeldata-prod-$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_storage_bucket.modeldata-prod"; then
            echo "  Importing modeldata-prod bucket..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_storage_bucket.modeldata-prod \
                "modeldata-prod-$PROJECT_ID" 2>/dev/null || true
        else
            echo "  modeldata-prod bucket already in state, skipping import"
        fi
    fi
    
    # Module 3 resources
    # Check if monitoring-function service account exists and import (only if not already in state)
    if gcloud iam service-accounts describe "monitoring-function@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
        if ! is_resource_in_state "google_service_account.monitoring-function"; then
            echo "  Importing monitoring-function service account..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_service_account.monitoring-function \
                "projects/$PROJECT_ID/serviceAccounts/monitoring-function@$PROJECT_ID.iam.gserviceaccount.com" \
                2>/dev/null || true
        else
            echo "  monitoring-function service account already in state, skipping import"
        fi
    fi
    
    # Check if cloud-function-bucket exists and import (only if not already in state)
    if gcloud storage buckets describe "gs://cloud-function-bucket-module3-$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_storage_bucket.cloud-function-bucket"; then
            echo "  Importing cloud-function-bucket..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_storage_bucket.cloud-function-bucket \
                "cloud-function-bucket-module3-$PROJECT_ID" 2>/dev/null || true
        else
            echo "  cloud-function-bucket already in state, skipping import"
        fi
    fi
    
    # Check if cloudai-portal function exists and import (only if not UNKNOWN/ERROR and not already in state)
    if gcloud functions describe cloudai-portal --region="$REGION" &>/dev/null; then
        func_state=$(gcloud functions describe cloudai-portal --region="$REGION" --format="value(state)" 2>/dev/null)
        if [ "$func_state" != "UNKNOWN" ] && [ "$func_state" != "ERROR" ]; then
            if ! is_resource_in_state "google_cloudfunctions2_function.cloudai_portal"; then
                echo "  Attempting to import cloudai-portal function (state: $func_state)..."
                terraform import \
                    -var="project_id=$PROJECT_ID" \
                    -var="project_number=$PROJECT_NUMBER" \
                    google_cloudfunctions2_function.cloudai_portal \
                    "projects/$PROJECT_ID/locations/$REGION/functions/cloudai-portal" \
                    2>/dev/null || echo "    Import failed, will force delete"
            else
                echo "  cloudai-portal function already in state, skipping import"
            fi
        else
            echo "  cloudai-portal is in $func_state state - skipping import, will force delete"
        fi
    fi
    
    # Challenge 5 resources
    # Check if terraform-pipeline service account exists and import (only if not already in state)
    if gcloud iam service-accounts describe "terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
        if ! is_resource_in_state "google_service_account.impersonation-challenge-5"; then
            echo "  Importing terraform-pipeline service account..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_service_account.impersonation-challenge-5 \
                "projects/$PROJECT_ID/serviceAccounts/terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com" \
                2>/dev/null || true
        else
            echo "  terraform-pipeline service account already in state, skipping import"
        fi
    fi
    
    # Check if TerraformPipelineProjectAdmin role exists and import (only if not already in state)
    if gcloud iam roles describe TerraformPipelineProjectAdmin --project="$PROJECT_ID" &>/dev/null; then
        if ! is_resource_in_state "google_project_iam_custom_role.project-iam-setter-role-challenge5"; then
            echo "  Importing TerraformPipelineProjectAdmin role..."
            terraform import \
                -var="project_id=$PROJECT_ID" \
                -var="project_number=$PROJECT_NUMBER" \
                google_project_iam_custom_role.project-iam-setter-role-challenge5 \
                "projects/$PROJECT_ID/roles/TerraformPipelineProjectAdmin" \
                2>/dev/null || true
        else
            echo "  TerraformPipelineProjectAdmin role already in state, skipping import"
        fi
    fi
}

# Remove imported Module 1 resources from terraform/ state
remove_module1_from_main_state() {
    echo "Removing Module 1 resources from main terraform state..."
    
    # Check if terraform directory exists first
    if [ ! -d "${TFMAIN_DIR}" ]; then
        echo "  ${TFMAIN_DIR} directory does not exist, skipping state cleanup"
        return 0
    fi
    
    cd ${TFMAIN_DIR}
    
    # Initialize if needed
    if [ ! -d ".terraform" ]; then
        terraform init -input=false 2>/dev/null || {
            echo "  Warning: terraform init failed, continuing anyway"
        }
    fi
    
    # Remove Module 1 resources from state (reverse of imports done in setup)
    echo "  Removing bucket-service-account from state..."
    terraform state rm google_service_account.bucket-service-account 2>/dev/null || true
    
    echo "  Removing dev-bucket-access role from state..."
    terraform state rm google_project_iam_custom_role.dev-bucket-access 2>/dev/null || true
    
    echo "  Removing modeldata buckets from state..."
    terraform state rm google_storage_bucket.modeldata-dev 2>/dev/null || true
    terraform state rm google_storage_bucket.modeldata-prod 2>/dev/null || true
    
    echo "  Removing IAM bindings from state..."
    terraform state rm google_storage_bucket_iam_member.dev-bucket-access 2>/dev/null || true
    terraform state rm google_storage_bucket_iam_member.prod-bucket-access 2>/dev/null || true
    
    echo "  Removing service account key from state..."
    terraform state rm google_service_account_key.bucket-sa-key 2>/dev/null || true
    
    cd ..
    echo "Module 1 resources removed from main terraform state"
}

# Try terraform destroy with state import if needed
destroy_with_terraform() {
    local dir=$1
    echo "##########################################################"
    echo "> Attempting terraform destroy in $dir..."
    echo "##########################################################"
    
    if [ ! -d "$dir" ]; then
        echo "Directory $dir does not exist, skipping..."
        return 0
    fi
    
    cd "$dir"
    
    # Initialize if needed
    if [ ! -d ".terraform" ]; then
        echo "Initializing terraform in $dir..."
        terraform init -input=false 2>/dev/null || {
            echo "  Warning: terraform init failed in $dir, continuing with cleanup"
            cd ..
            return 1
        }
    fi
    
    # Check if state is empty but resources exist
    local has_resources=$(terraform state list 2>/dev/null | grep -c "google_" || echo "0")
    
    # Handle main terraform directory
    if [ "$has_resources" -eq "0" ] && [ "$dir" = "${TFMAIN_DIR}" ]; then
        echo "Warning: State appears empty, checking for orphaned resources..."
        # Only try import if resources actually exist
        if gcloud iam service-accounts describe "bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null || \
           gcloud iam service-accounts describe "monitoring-function@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null || \
           gcloud iam service-accounts describe "terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null || \
           gcloud iam roles describe DevBucketAccess --project="$PROJECT_ID" &>/dev/null || \
           gcloud iam roles describe TerraformPipelineProjectAdmin --project="$PROJECT_ID" &>/dev/null || \
           gcloud storage buckets describe "gs://modeldata-dev-$PROJECT_ID" &>/dev/null || \
           gcloud storage buckets describe "gs://modeldata-prod-$PROJECT_ID" &>/dev/null || \
           gcloud storage buckets describe "gs://cloud-function-bucket-module3-$PROJECT_ID" &>/dev/null; then
            import_terraform_resources
        fi
    fi
    
    # Handle module2 directory
    if [ "$has_resources" -eq "0" ] && [ "$dir" = "${TFMOD2_DIR}" ]; then
        echo "Warning: State appears empty, checking for orphaned resources..."
        # Only try import if resources actually exist
        if gcloud compute instances describe app-prod-instance-module2 --zone=us-east1-b --project="$PROJECT_ID" &>/dev/null || \
           gcloud storage buckets describe "gs://file-uploads-$PROJECT_ID" &>/dev/null || \
           gcloud secrets describe ssh-key --project="$PROJECT_ID" &>/dev/null; then
            import_module2_resources
        fi
    fi
    
    # Run destroy
    echo "Running terraform destroy..."
    terraform destroy \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        -auto-approve || {
        echo "Terraform destroy encountered issues in $dir"
        cd ..
        return 1
    }
    
    cd ..
    return 0
}

# Main script starts here
echo "##########################################################"
echo "> Starting GCP AI Security Lab resource cleanup"
echo "##########################################################"

# Get project info
if [ -z "$TF_VAR_project_id" ]; then
    read -p "Your GCP project ID: " PROJECT_ID
else
    PROJECT_ID="$TF_VAR_project_id"
    echo "Using project ID from environment: $PROJECT_ID"
fi


# Get project number
if [ -z "$PROJECT_NUMBER" ]; then
    PROJECT_NUMBER="$(gcloud projects describe $PROJECT_ID --quiet 2>&1 | grep -Eo "project(s\/|Number: ')[0-9]{10,}" | grep -Eo '[0-9]+')"
    echo "Parsed project number: $PROJECT_NUMBER"
else
    echo "Detected project number: $PROJECT_NUMBER"
fi

TF_VAR_project_number="${PROJECT_NUMBER}"

if [ -z "$REGION" ]; then
    REGION="us-east1"
    echo "Using region: $REGION"
else
    echo "Using region from environment: $REGION"
fi

if [ -z "$PROJECT_NUMBER" ]; then
    echo "Error: Could not get project number for project $PROJECT_ID"
    echo "Please ensure you have access to the project and gcloud is configured correctly."
    exit 1
fi

echo "Project ID: $PROJECT_ID"
echo "Project Number: $PROJECT_NUMBER"
echo "Region: $REGION"
echo ""

# Restore admin account configuration if student-workshop exists
echo "##########################################################"
echo "> Checking for student-workshop configuration..."
echo "##########################################################"

# Get list of configurations
CONFIGS=$(gcloud config configurations list --format="value(name)" 2>/dev/null)

if echo "$CONFIGS" | grep -q "^student-workshop$"; then
    # Revoke student-workshop credentials first to prevent auth issues
    echo "Revoking student-workshop credentials..."
    gcloud auth revoke student-workshop@$PROJECT_ID.iam.gserviceaccount.com --quiet 2>/dev/null || true
    
    echo "Found student-workshop configuration. Restoring to default configuration..."
    
    # Always switch to default configuration instead of admin-backup
    gcloud config configurations activate default
    
    # Get the account from default configuration
    DEFAULT_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
    
    # Explicitly set the account (configuration switch alone isn't always enough)
    if [ ! -z "$DEFAULT_ACCOUNT" ]; then
        echo "Setting active account to: $DEFAULT_ACCOUNT"
        gcloud config set account "$DEFAULT_ACCOUNT" 2>/dev/null
    else
        echo "ERROR: No account found in default configuration"
        echo "Please run: gcloud auth login"
        exit 1
    fi
    
    # Verify the switch worked
    ACTIVE_ACCOUNT=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null)
    if [[ "$ACTIVE_ACCOUNT" == *"student-workshop"* ]]; then
        echo "ERROR: Failed to switch away from student-workshop account"
        echo "Manual intervention required: gcloud auth login"
        exit 1
    fi
    
    # Delete both student-workshop and admin-backup configurations for clean state
    echo "Cleaning up configurations..."
    gcloud config configurations delete student-workshop --quiet 2>/dev/null || true
    
    # Also delete admin-backup if it exists (since we're not using it anymore)
    if echo "$CONFIGS" | grep -q "^admin-backup$"; then
        gcloud config configurations delete admin-backup --quiet 2>/dev/null || true
        echo "  - Deleted: admin-backup (no longer needed)"
    fi
    
    echo "✓ Successfully restored default configuration"
    echo "  - Activated: default"
    echo "  - Deleted: student-workshop"
else
    echo "No student-workshop configuration found. Continuing with current configuration."
fi

echo ""

# Detect zombie resources before cleanup
detect_zombie_resources
echo ""

# Pre-destroy verification for known problematic resources
echo "##########################################################"
echo "> Pre-destroy verification for known problematic resources..."
echo "##########################################################"

# Check for cloudai-portal function specifically
for region in us-east1 us-central1 us-west1; do
    if gcloud functions describe cloudai-portal --region="$region" --project="$PROJECT_ID" &>/dev/null; then
        echo "WARNING: Found existing cloudai-portal in $region - will force delete"
        gcloud functions delete cloudai-portal \
            --region="$region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    fi
done

# List resources that will be destroyed
echo "##########################################################"
echo "> Scanning for resources to destroy..."
echo "##########################################################"

echo "Compute instances:"
gcloud compute instances list --filter="name:module2" --format="table(name,zone,status)" 2>/dev/null || echo "  None found"

echo ""
echo "Storage buckets:"
gcloud storage ls 2>/dev/null | grep -E "file-uploads-$PROJECT_ID|cloud-function-bucket-module3-$PROJECT_ID|modeldata-.*-$PROJECT_ID" || echo "  None found"

echo ""
echo "Secrets:"
gcloud secrets list --filter="name:ssh-key" --format="table(name)" 2>/dev/null || echo "  None found"

echo ""
echo "Cloud Functions (all states):"
gcloud functions list --format="table(name,state,region)" 2>/dev/null || echo "  None found"

# Highlight zombie functions
echo ""
echo "Zombie Functions (UNKNOWN state):"
gcloud functions list --filter="state:UNKNOWN" --format="table(name,region)" 2>/dev/null || echo "  None found"

echo ""
echo "Cloud Run services:"
gcloud run services list --format="table(name,region)" 2>/dev/null || echo "  None found"

echo ""
if [[ "$FIRST_SCRIPT_ARG" != '--force' ]]; then
    read -p "Continue with destroy? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Destroy cancelled by user"
        exit 0
    fi
fi

# Track if we need fallback cleanup
NEEDS_CLEANUP=false

# Remove imported Module 1 resources from main terraform state first
# This prevents conflicts when terraform_module1 tries to destroy the same resources
if [ -d "${TFMAIN_DIR}" ] && [ -f "${TFMAIN_DIR}/terraform.tfstate" ]; then
    echo ""
    echo "##########################################################"
    echo "> Preparing states for clean destroy..."
    echo "##########################################################"
    remove_module1_from_main_state
fi

# Now destroy in the order where each directory owns its resources
# Module 1 first (owns the Module 1 resources)
if [ -d "${TFMOD1_DIR}" ]; then
    destroy_with_terraform "${TFMOD1_DIR}" || NEEDS_CLEANUP=true
fi

# Module 2 second
if [ -d "${TFMOD2_DIR}" ]; then
    destroy_with_terraform "${TFMOD2_DIR}" || NEEDS_CLEANUP=true
fi

# Main terraform last (Module 1 resources already removed from state)
if [ -d "${TFMAIN_DIR}" ]; then
    destroy_with_terraform "${TFMAIN_DIR}" || NEEDS_CLEANUP=true
fi

# Always run comprehensive cleanup to catch everything
echo ""
echo "##########################################################"
echo "> Running comprehensive cleanup to ensure nothing remains..."
echo "##########################################################"
cleanup_all_gcp_resources


# Clean up local files and directories
echo ""
echo "##########################################################"
echo "> Cleaning up local files and directories..."
echo "##########################################################"

# Remove terraform state files
echo "Removing terraform state files..."
rm -f ${TFMAIN_DIR}/terraform.tfstate* 2>/dev/null || true
rm -f ${TFMOD2_DIR}/terraform.tfstate* 2>/dev/null || true
rm -f ${TFMOD1_DIR}/terraform.tfstate* 2>/dev/null || true

# Remove terraform lock files
echo "Removing terraform lock files..."
rm -f ${TFMAIN_DIR}/.terraform.lock.hcl 2>/dev/null || true
rm -f ${TFMOD2_DIR}/.terraform.lock.hcl 2>/dev/null || true
rm -f ${TFMOD1_DIR}/.terraform.lock.hcl 2>/dev/null || true

# Remove terraform directories
echo "Removing .terraform directories..."
rm -rf ${TFMAIN_DIR}/.terraform 2>/dev/null || true
rm -rf ${TFMOD2_DIR}/.terraform 2>/dev/null || true
rm -rf ${TFMOD1_DIR}/.terraform 2>/dev/null || true

# Remove temporary files
echo "Removing temporary_files directory..."
rm -rf ${TEMPFILE_DIR} 2>/dev/null || true

# Remove terraform_module1 directory (created during setup)
echo "Removing terraform_module1 directory..."
rm -rf ${TFMOD1_DIR} 2>/dev/null || true

# Remove ANSWER_DIR if it's empty
echo "Removing answer files directory if empty..."
rmdir ${ANSWER_DIR} 2>/dev/null || true

echo ""
echo "##########################################################"
echo "> Destroy complete!"
echo "##########################################################"
echo ""
echo "All resources have been destroyed and local files cleaned up."
echo "You can now run ./challenge-setup.sh to deploy fresh resources."
