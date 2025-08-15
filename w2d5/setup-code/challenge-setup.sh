#!/bin/bash

# variables
if [ -z "$TF_VAR_project_id" ] ; then
    read -p "Your GCP project ID: " PROJECT_ID
else
    PROJECT_ID="${TF_VAR_project_id}"
    echo "Read TF Var ProjectID = ${PROJECT_ID}"
fi

PROJECT_NUMBER="$(gcloud projects describe $PROJECT_ID --quiet 2>&1 | grep -Eo "project(s\/|Number: ')[0-9]{10,}" | grep -Eo '[0-9]+')"
if [ -z "$PROJECT_NUMBER" ]; then
    echo "ERROR: Failed to get project number for project: $PROJECT_ID"
    echo "Please ensure the project exists and you have access to it."
    exit 1
fi

THIS_DIR="$(realpath .)"
ANSWER_DIR="${THIS_DIR}/.answerfiles-dontreadpls-spoilers-sadge"

#  create directory for temporary files
TEMPFILE_DIR="${ANSWER_DIR}/temporary_files"
mkdir -p ${TEMPFILE_DIR}
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create ${TEMPFILE_DIR} directory"
    exit 1
fi

# INFO: TF Maindir already exists at this path, so no need to create it
TFMAIN_DIR="${ANSWER_DIR}/terraform"

# Module 1 setup - Create ${TFMOD1_DIR} directory for separate state
echo "##########################################################"
echo "> Beginning terraform setup for - Module 1."
echo "##########################################################"

# INFO: Mod1 setup involves creating a duplicate, so we 'cp' its files
TFMOD1_DIR="${ANSWER_DIR}/terraform_module1"
mkdir -p ${TFMOD1_DIR}
cp "${TFMAIN_DIR}/module1.tf" ${TFMOD1_DIR}/
cp "${TFMAIN_DIR}/variables.tf" ${TFMOD1_DIR}/
cp "${TFMAIN_DIR}/provider.tf" ${TFMOD1_DIR}/

# Force cleanup any orphaned Module 1 service accounts before terraform runs
# This ensures terraform can create them fresh without conflicts
echo "  Checking for orphaned Module 1 service accounts..."

##### PHASE ALPHA -> CLEANUP

# Clean up student-workshop service account
if gcloud iam service-accounts describe "student-workshop@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
    echo "  Found orphaned student-workshop service account, removing..."
    # First remove any IAM policy bindings for this service account
    MEMBER="serviceAccount:student-workshop@$PROJECT_ID.iam.gserviceaccount.com"
    for role in $(gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:$MEMBER" --format="value(bindings.role)" 2>/dev/null); do
        echo "    Removing IAM binding for role: $role"
        gcloud projects remove-iam-policy-binding $PROJECT_ID --member="$MEMBER" --role="$role"
        if [ $? -ne 0 ]; then
            echo "    WARNING: Failed to remove IAM binding for role: $role (may already be removed)"
        fi
    done
    # Delete the service account
    gcloud iam service-accounts delete \
        "student-workshop@$PROJECT_ID.iam.gserviceaccount.com" \
        --project="$PROJECT_ID"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to delete student-workshop service account"
        echo "This may prevent terraform from creating resources correctly."
        exit 1
    fi
    echo "  Cleaned up student-workshop account"
fi

# Clean up bucket-service-account 
if gcloud iam service-accounts describe "bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
    echo "  Found orphaned bucket-service-account, removing..."
    # First remove any IAM policy bindings for this service account
    MEMBER="serviceAccount:bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com"
    for role in $(gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:$MEMBER" --format="value(bindings.role)" 2>/dev/null); do
        echo "    Removing IAM binding for role: $role"
        gcloud projects remove-iam-policy-binding $PROJECT_ID --member="$MEMBER" --role="$role"
        if [ $? -ne 0 ]; then
            echo "    WARNING: Failed to remove IAM binding for role: $role (may already be removed)"
        fi
    done
    # Delete the service account
    gcloud iam service-accounts delete \
        "bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" \
        --project="$PROJECT_ID"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to delete bucket-service-account"
        echo "This may prevent terraform from creating resources correctly."
        exit 1
    fi
    echo "  Cleaned up bucket-service-account"
fi

echo "  Module 1 service account cleanup complete"

##### PHASE BETA -> CREATION

cd ${TFMOD1_DIR}
terraform init -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform init failed for Module 1"
    exit 1
fi

terraform plan -out tf.out -var project_id="$PROJECT_ID" -var project_number="$PROJECT_NUMBER" -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform plan failed for Module 1"
    exit 1
fi
terraform apply -input=false "tf.out"
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform apply failed for Module 1"
    exit 1
fi

cd ../


# Call Module 1 specific setup script
bash ${ANSWER_DIR}/mod1-setup.sh "$PROJECT_ID" "$PROJECT_NUMBER"
if [ $? -ne 0 ]; then
    echo "ERROR: Module 1 setup script failed"
    exit 1
fi

# the compute engine for module 2 gets created in its own terraform run
# this is done to get an extra state file that we can leak on the storage bucket
# create it first so that we have the state file, and to give it some time to boot
# create ssh key for vulnerable compute VM
if [ ! -f ${TEMPFILE_DIR}/leaked_ssh_key ]; then
    ssh-keygen -t ed25519 -C "alice" -f ${TEMPFILE_DIR}/leaked_ssh_key -N ''
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to generate SSH key"
        exit 1
    fi
fi

echo "##########################################################"
echo "> Beginning terraform setup for - Module 2."
echo "##########################################################"

# INFO: Mod2 already exists at this path, no copying needed.
TFMOD2_DIR="${ANSWER_DIR}/terraform_module2"

cd ${TFMOD2_DIR}
terraform init -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform init failed for Module 2"
    exit 1
fi
terraform plan -out tf.out -var project_id="$PROJECT_ID" -var project_number="$PROJECT_NUMBER" -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform plan failed for Module 2"
    exit 1
fi
terraform apply -input=false "tf.out"
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform apply failed for Module 2"
    exit 1
fi
cd ../

# set up resources with terraform
echo "##########################################################"
echo "> Beginning terraform setup for - challenges 4 and 5."
echo "##########################################################"

# INFO: TF maindir already exists; no need to create or populate.
cd ${TFMAIN_DIR}
terraform init -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform init failed for main terraform"
    exit 1
fi

# Import Module 1 resources that were created in ${TFMOD1_DIR}
echo "> Checking for existing Module 1 resources to import..."

# Import student-workshop service account if it exists
if gcloud iam service-accounts describe "student-workshop@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
    echo "  Importing student-workshop service account..."
    terraform import \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        google_service_account.student-workshop \
        "projects/$PROJECT_ID/serviceAccounts/student-workshop@$PROJECT_ID.iam.gserviceaccount.com"
fi

# Import bucket-service-account if it exists
if gcloud iam service-accounts describe "bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
    echo "  Importing bucket-service-account..."
    terraform import \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        google_service_account.bucket-service-account \
        "projects/$PROJECT_ID/serviceAccounts/bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com"
fi

# Import DevBucketAccess custom role if it exists
if gcloud iam roles describe DevBucketAccess --project="$PROJECT_ID" &>/dev/null; then
    echo "  Importing DevBucketAccess role..."
    terraform import \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        google_project_iam_custom_role.dev-bucket-access \
        "projects/$PROJECT_ID/roles/DevBucketAccess"
fi

# Import modeldata-dev bucket if it exists
if gsutil ls -b "gs://modeldata-dev-$PROJECT_ID" &>/dev/null; then
    echo "  Importing modeldata-dev bucket..."
    terraform import \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        google_storage_bucket.modeldata-dev \
        "$PROJECT_ID/modeldata-dev-$PROJECT_ID"
fi

# Import modeldata-prod bucket if it exists  
if gsutil ls -b "gs://modeldata-prod-$PROJECT_ID" &>/dev/null; then
    echo "  Importing modeldata-prod bucket..."
    terraform import \
        -var="project_id=$PROJECT_ID" \
        -var="project_number=$PROJECT_NUMBER" \
        google_storage_bucket.modeldata-prod \
        "$PROJECT_ID/modeldata-prod-$PROJECT_ID"
fi

# Import IAM bindings if they exist
# Note: These may fail if the exact member format doesn't match, but that's ok
echo "  Attempting to import IAM bindings..."
terraform import \
    -var="project_id=$PROJECT_ID" \
    -var="project_number=$PROJECT_NUMBER" \
    google_storage_bucket_iam_member.dev-bucket-access \
    "b/modeldata-dev-$PROJECT_ID roles/storage.objectViewer serviceAccount:bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" \
    2>/dev/null || true

terraform import \
    -var="project_id=$PROJECT_ID" \
    -var="project_number=$PROJECT_NUMBER" \
    google_storage_bucket_iam_member.prod-bucket-access \
    "b/modeldata-prod-$PROJECT_ID roles/storage.objectViewer serviceAccount:bucket-service-account@$PROJECT_ID.iam.gserviceaccount.com" \
    2>/dev/null || true

echo "> Import complete, continuing with terraform plan..."

terraform plan -out tf.out -var project_id="$PROJECT_ID" -var project_number="$PROJECT_NUMBER" -input=false
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform plan failed for main terraform"
    exit 1
fi
terraform apply -input=false "tf.out"
if [ $? -ne 0 ]; then
    echo "ERROR: Terraform apply failed for main terraform"
    exit 1
fi
cd ../

# Call Module 2 specific setup script
bash ${ANSWER_DIR}/mod2-setup.sh "$PROJECT_ID" "$PROJECT_NUMBER"
if [ $? -ne 0 ]; then
    echo "ERROR: Module 2 setup script failed"
    exit 1
fi

echo "##########################################################"
echo "> Setup for module 3."
echo "##########################################################"

ZONE=$(gcloud compute instances list --project $PROJECT_ID | grep module2 | awk '{print$2}')
if [ -z "$ZONE" ]; then
    echo "ERROR: Failed to get zone for module2 instance"
    exit 1
fi
COMPUTE_IP=$(gcloud compute instances describe app-prod-instance-module2 --zone $ZONE --project $PROJECT_ID | grep natIP | awk '{print $2}')
if [ -z "$COMPUTE_IP" ]; then
    echo "ERROR: Failed to get IP address for module2 instance"
    exit 1
fi

# Get the monitoring function URL and save it to a file
LOCATION="us-east1"
FUNCTION_URL=$(gcloud run services describe monitoring-function --region=$LOCATION --format='value(status.url)')
if [ -z "$FUNCTION_URL" ]; then
    echo "ERROR: Failed to get monitoring function URL"
    exit 1
fi
echo "Function URL: $FUNCTION_URL"

# copy function invocation script on compute engine
scp -i ${TEMPFILE_DIR}/leaked_ssh_key -o StrictHostKeyChecking=no "${ANSWER_DIR}/invoke_monitoring_function.sh" alice@$COMPUTE_IP:/tmp
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy invoke_monitoring_function.sh to compute instance"
    exit 1
fi
# make the script executable and not writeable and owned by root
ssh -i ${TEMPFILE_DIR}/leaked_ssh_key -o StrictHostKeyChecking=no alice@$COMPUTE_IP "sudo mv /tmp/invoke_monitoring_function.sh /usr/local/bin/; cd /home/alice && ln -s /usr/local/bin/invoke_monitoring_function.sh; sudo chmod 755 /usr/local/bin/invoke_monitoring_function.sh; sudo chown root:root /usr/local/bin/invoke_monitoring_function.sh"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set up invoke_monitoring_function.sh on compute instance"
    exit 1
fi
# Save the function URL to a file on the VM for the invocation script
ssh -i ${TEMPFILE_DIR}/leaked_ssh_key -o StrictHostKeyChecking=no alice@$COMPUTE_IP "echo '$FUNCTION_URL' > /home/alice/.function_url"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to save function URL on compute instance"
    exit 1
fi
# drop sudo privileges for alice
ssh -i ${TEMPFILE_DIR}/leaked_ssh_key -o StrictHostKeyChecking=no alice@$COMPUTE_IP "sudo deluser alice google-sudoers"
if [ $? -ne 0 ]; then
    echo "WARNING: Failed to remove alice from google-sudoers (may not exist)"
fi
# copy the function source code directly on the bucket
gsutil cp ${TFMAIN_DIR}/script/main.py gs://cloud-function-bucket-module3-$PROJECT_ID/
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy main.py to cloud function bucket"
    exit 1
fi
# remove the function zip file from the storage bucket to not mislead players to try and extract it
gsutil rm gs://cloud-function-bucket-module3-$PROJECT_ID/main.zip
if [ $? -ne 0 ]; then
    echo "WARNING: Failed to remove main.zip (may not exist)"
fi

# Get CloudAI Portal URL
PORTAL_URL=$(cd ${TFMAIN_DIR} && terraform output -raw cloudai_portal_url 2>/dev/null)
if [ -z "$PORTAL_URL" ]; then
    PORTAL_URL="Portal not deployed"
fi

echo "##########################################################"
echo "> Switching to student-workshop service account"
echo "##########################################################"

echo "##########################################################"
echo "> Ensuring clean admin configuration backup"
echo "##########################################################"

# ALWAYS start from default configuration to ensure clean state
echo "> Switching to default configuration..."
gcloud config configurations activate default
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate default configuration"
    exit 1
fi

# Get the admin account from default configuration
DEFAULT_ACCOUNT=$(gcloud config get-value account 2>/dev/null)
DEFAULT_PROJECT=$(gcloud config get-value project 2>/dev/null)

if [ -z "$DEFAULT_ACCOUNT" ]; then
    echo "ERROR: No account found in default configuration"
    echo "Please run: gcloud auth login"
    exit 1
fi

echo "  Default configuration account: $DEFAULT_ACCOUNT"

# Delete any existing admin-backup to ensure it's clean
if gcloud config configurations describe admin-backup &>/dev/null; then
    echo "  Removing existing admin-backup configuration..."
    gcloud config configurations delete admin-backup
    if [ $? -ne 0 ]; then
        echo "    WARNING: Failed to delete admin-backup configuration (continuing)"
    fi
fi

# Create fresh admin-backup from default
echo "  Creating fresh admin-backup configuration..."
gcloud config configurations create admin-backup 2>/dev/null
if [ $? -ne 0 ]; then
    echo "WARNING: admin-backup configuration may already exist (continuing)"
fi
gcloud config configurations activate admin-backup
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate admin-backup configuration"
    exit 1
fi
gcloud config set project "$PROJECT_ID"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set project in admin-backup configuration"
    exit 1
fi
gcloud config set account "$DEFAULT_ACCOUNT"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set account in admin-backup configuration"
    exit 1
fi

echo "✓ Admin backup created with account: $DEFAULT_ACCOUNT"

gcloud config configurations list

# Extract student-workshop service account key from terraform
echo "> Extracting student-workshop service account credentials..."
cd ${TFMOD1_DIR}
STUDENT_KEY=$(terraform output -raw student_workshop_key 2>/dev/null)
if [ -z "$STUDENT_KEY" ]; then
    echo "ERROR: Failed to get student-workshop service account key from terraform"
    exit 1
fi
STUDENT_EMAIL=$(terraform output -raw student_workshop_email 2>/dev/null)
if [ -z "$STUDENT_EMAIL" ]; then
    echo "ERROR: Failed to get student-workshop service account email from terraform"
    exit 1
fi
cd ../

# Save the key to a file
echo "$STUDENT_KEY" | base64 -d > ${TEMPFILE_DIR}/student-workshop-key.json
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to decode student-workshop service account key"
    exit 1
fi

# Create new configuration for student workshop
echo "> Creating student-workshop configuration..."
gcloud config configurations create student-workshop --activate 2>/dev/null
if [ $? -ne 0 ]; then
    echo "WARNING: student-workshop configuration may already exist (continuing)"
    gcloud config configurations activate student-workshop
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to activate student-workshop configuration"
        exit 1
    fi
fi
gcloud config set project "$PROJECT_ID"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set project in student-workshop configuration"
    exit 1
fi

# Activate the student-workshop service account
echo "> Activating student-workshop service account..."
gcloud auth activate-service-account "$STUDENT_EMAIL" --key-file=${TEMPFILE_DIR}/student-workshop-key.json
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate student-workshop service account"
    echo "Check that the key file exists and is valid."
    exit 1
fi

# Set this as the active account
gcloud config set account "$STUDENT_EMAIL"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set student-workshop as active account"
    exit 1
fi

echo ""
echo "##########################################################"
echo "> Account switch complete!"
echo "##########################################################"
echo "> Current active account: $STUDENT_EMAIL"
echo "> This account has LIMITED permissions (dev bucket only)"
echo "> Students must find and use bucket-service-account"
echo "> credentials in the dev bucket to access prod resources"
echo ""
echo "> To switch back to admin: gcloud config configurations activate admin-backup"
echo ""

echo "##########################################################"
echo "> Challenge setup complete!"
echo "##########################################################"
echo ""
echo "CloudAI Labs Portal: $PORTAL_URL"
echo "Start by exploring: gs://modeldata-dev-$PROJECT_ID/"
echo "Portal info available at: gs://modeldata-dev-$PROJECT_ID/portal_info.txt"
echo ""