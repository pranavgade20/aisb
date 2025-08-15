#!/bin/bash

# CloudAI Portal Rapid Redeploy Script
# Quickly redeploys only the CloudAI webapp/portal Cloud Function
# Designed to complete in under 1 minute for rapid iteration

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script start time
START_TIME=$(date +%s)

# Function to print colored messages
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print elapsed time
print_elapsed() {
    local current_time=$(date +%s)
    local elapsed=$((current_time - START_TIME))
    echo -e "${BLUE}[Elapsed: ${elapsed}s]${NC}"
}

# Function to check command success
check_success() {
    if [ $? -ne 0 ]; then
        print_status "$RED" "ERROR: $1"
        print_elapsed
        exit 1
    fi
}

echo "Switching to default gcloud config so this script works!"
gcloud config configurations activate default

# Parse command line arguments
QUICK_MODE=false
HEALTH_CHECK=false
FIX_IAM_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            print_status "$YELLOW" "Quick mode enabled - skipping archive recreation"
            shift
            ;;
        --health-check)
            HEALTH_CHECK=true
            shift
            ;;
        --fix-iam)
            FIX_IAM_ONLY=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick        Skip archive recreation for faster deploys"
            echo "  --health-check Perform HTTP health check after deployment"
            echo "  --fix-iam      Only repair the IAM binding (quick fix for 403 errors)"
            echo "  --help         Show this help message"
            echo ""
            echo "This script rapidly redeploys the CloudAI portal Cloud Function"
            echo "without rebuilding the entire infrastructure."
            exit 0
            ;;
        *)
            print_status "$RED" "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

print_status "$GREEN" "==========================================="
print_status "$GREEN" "CloudAI Portal Rapid Redeploy Script"
print_status "$GREEN" "==========================================="

# Step 1: Get project configuration
print_status "$BLUE" "Step 1: Configuring project variables..."

# Check for PROJECT_ID
if [ -z "$PROJECT_ID" ] && [ -z "$TF_VAR_project_id" ]; then
    print_status "$RED" "ERROR: PROJECT_ID or TF_VAR_project_id must be set"
    echo "Set one of these environment variables and try again:"
    echo "  export PROJECT_ID=your-project-id"
    echo "  export TF_VAR_project_id=your-project-id"
    exit 1
fi

# Use TF_VAR_project_id if PROJECT_ID is not set
PROJECT_ID="${PROJECT_ID:-$TF_VAR_project_id}"

print_status "$GREEN" "  Project ID: $PROJECT_ID"

# Get PROJECT_NUMBER
print_status "$YELLOW" "  Getting project number..."
PROJECT_NUMBER="$(gcloud projects describe $PROJECT_ID --quiet 2>&1 | grep -Eo "project(s\/|Number: ')[0-9]{10,}" | grep -Eo '[0-9]+')"
check_success "Failed to get project number. Ensure gcloud is configured and you have access to project: $PROJECT_ID"

print_status "$GREEN" "  Project Number: $PROJECT_NUMBER"
print_elapsed

# Step 2: Navigate to terraform directory
print_status "$BLUE" "Step 2: Navigating to ${TF_DIR} directory..."
ANSWER_DIR=$(realpath .answerfiles-dontreadpls-spoilers-sadge)
TF_DIR="${ANSWER_DIR}/terraform"
cd "${TF_DIR}"
check_success "terraform directory not found. Are you in the correct repository?"

# Get region for use in IAM commands
REGION="${TF_VAR_region:-us-east1}"
print_status "$GREEN" "  Region: $REGION"
print_elapsed

# Step 3: Check terraform initialization
print_status "$BLUE" "Step 3: Checking terraform initialization..."
if [ ! -d ".terraform" ]; then
    print_status "$YELLOW" "  Terraform not initialized. Running terraform init..."
    terraform init -input=false
    check_success "Terraform initialization failed"
else
    print_status "$GREEN" "  Terraform already initialized"
fi
print_elapsed

# Quick IAM fix mode
if [ "$FIX_IAM_ONLY" = true ]; then
    print_status "$BLUE" "IAM Fix Mode: Repairing public access binding only..."
    
    # Apply IAM binding via gcloud
    gcloud run services add-iam-policy-binding cloudai-portal \
        --region="$REGION" \
        --member="allUsers" \
        --role="roles/run.invoker" \
        --quiet
    
    if [ $? -eq 0 ]; then
        print_status "$GREEN" "IAM binding successfully applied!"
        
        # Import to terraform state
        terraform import google_cloud_run_service_iam_member.cloudai_portal_public \
            "v1/projects/$PROJECT_ID/locations/$REGION/services/cloudai-portal/roles/run.invoker/allUsers" 2>/dev/null
        
        PORTAL_URL=$(terraform output -raw cloudai_portal_url 2>/dev/null)
        if [ ! -z "$PORTAL_URL" ]; then
            print_status "$GREEN" "Portal should now be accessible at: $PORTAL_URL"
        fi
    else
        print_status "$RED" "Failed to apply IAM binding"
    fi
    
    print_elapsed
    exit 0
fi

# Step 4: Create/Update archive if not in quick mode
if [ "$QUICK_MODE" = false ]; then
    print_status "$BLUE" "Step 4: Refreshing CloudAI portal archive..."
    
    # Ensure the files directory exists
    mkdir -p files
    
    # Trigger archive recreation by touching the source files
    if [ -d "cloudai-portal" ]; then
        touch cloudai-portal/main.py
        print_status "$GREEN" "  Source files updated to trigger archive recreation"
    else
        print_status "$YELLOW" "  Warning: cloudai-portal directory not found"
    fi
else
    print_status "$YELLOW" "Step 4: Skipping archive recreation (--quick mode)"
fi
print_elapsed

# Step 5: Apply terraform changes with targeted replacement
print_status "$BLUE" "Step 5: Deploying CloudAI portal function..."
print_status "$YELLOW" "  This will replace the Cloud Function and update dependencies"

# Build the terraform command
TF_COMMAND="terraform apply -auto-approve -input=false"
TF_COMMAND="$TF_COMMAND -var project_id=\"$PROJECT_ID\""
TF_COMMAND="$TF_COMMAND -var project_number=\"$PROJECT_NUMBER\""

# Force replacement of the function to ensure fresh deployment
TF_COMMAND="$TF_COMMAND -replace=google_cloudfunctions2_function.cloudai_portal"

# Target specific resources to avoid full infrastructure rebuild
TF_COMMAND="$TF_COMMAND -target=data.archive_file.cloudai_portal"
TF_COMMAND="$TF_COMMAND -target=google_storage_bucket_object.cloudai_portal_code"
TF_COMMAND="$TF_COMMAND -target=google_cloudfunctions2_function.cloudai_portal"

# Execute the terraform command
print_status "$YELLOW" "  Executing terraform apply (this may take 30-45 seconds)..."
eval $TF_COMMAND
check_success "Terraform deployment failed"
print_elapsed

# Step 5b: Ensure public access IAM binding exists
print_status "$BLUE" "Step 5b: Verifying public access permissions..."

# Check if IAM binding exists in terraform state
IAM_STATE_EXISTS=$(terraform state list | grep -c "google_cloud_run_service_iam_member.cloudai_portal_public")

if [ "$IAM_STATE_EXISTS" -eq 0 ]; then
    print_status "$YELLOW" "  IAM binding not in terraform state - importing or creating..."
    
    # Try to import existing binding first
    terraform import google_cloud_run_service_iam_member.cloudai_portal_public \
        "v1/projects/$PROJECT_ID/locations/$REGION/services/cloudai-portal/roles/run.invoker/allUsers" 2>/dev/null
    
    if [ $? -ne 0 ]; then
        print_status "$YELLOW" "  No existing binding found - will create new one"
    fi
    
    # Apply just the IAM binding
    terraform apply -auto-approve -input=false \
        -var project_id="$PROJECT_ID" \
        -var project_number="$PROJECT_NUMBER" \
        -target=google_cloud_run_service_iam_member.cloudai_portal_public
    check_success "Failed to create IAM binding"
else
    print_status "$GREEN" "  IAM binding exists in state"
fi

# Verify the IAM binding is actually applied
BINDING_EXISTS=$(gcloud run services get-iam-policy cloudai-portal \
    --region="$REGION" --format=json 2>/dev/null | grep -c "allUsers")

if [ "$BINDING_EXISTS" -eq 0 ]; then
    print_status "$YELLOW" "  IAM binding missing from Cloud Run service - applying directly..."
    gcloud run services add-iam-policy-binding cloudai-portal \
        --region="$REGION" \
        --member="allUsers" \
        --role="roles/run.invoker" \
        --quiet
    check_success "Failed to add IAM binding via gcloud"
    print_status "$GREEN" "  Public access restored"
else
    print_status "$GREEN" "  Public access confirmed"
fi

print_elapsed

# Step 6: Get the portal URL
print_status "$BLUE" "Step 6: Retrieving portal URL..."
PORTAL_URL=$(terraform output -raw cloudai_portal_url 2>/dev/null)
if [ -z "$PORTAL_URL" ]; then
    print_status "$YELLOW" "  Warning: Could not retrieve portal URL from terraform output"
    print_status "$YELLOW" "  You can get it manually with: terraform output cloudai_portal_url"
else
    print_status "$GREEN" "  Portal URL: $PORTAL_URL"
    
    # Save URL to temporary file for easy access
    echo "$PORTAL_URL" > ../temporary_files/portal_url.txt
    print_status "$GREEN" "  URL saved to: temporary_files/portal_url.txt"
fi
print_elapsed

# Step 7: Optional health check
if [ "$HEALTH_CHECK" = true ] && [ ! -z "$PORTAL_URL" ]; then
    print_status "$BLUE" "Step 7: Performing health check..."
    print_status "$YELLOW" "  Waiting 5 seconds for function to be ready..."
    sleep 5
    
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PORTAL_URL" 2>/dev/null)
    if [ "$HTTP_STATUS" = "200" ]; then
        print_status "$GREEN" "  Health check passed! (HTTP $HTTP_STATUS)"
    elif [ "$HTTP_STATUS" = "403" ]; then
        print_status "$RED" "  Health check failed: Access denied (HTTP 403)"
        print_status "$RED" "  IAM binding may be missing - run script again or check permissions"
    else
        print_status "$YELLOW" "  Health check returned HTTP $HTTP_STATUS (function may still be starting)"
    fi
else
    if [ "$HEALTH_CHECK" = true ]; then
        print_status "$YELLOW" "Step 7: Skipping health check (no URL available)"
    fi
fi

# Calculate total execution time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

print_status "$GREEN" "==========================================="
print_status "$GREEN" "Deployment completed successfully!"
print_status "$GREEN" "Total execution time: ${TOTAL_TIME} seconds"
if [ ! -z "$PORTAL_URL" ]; then
    print_status "$GREEN" "Portal URL: $PORTAL_URL"
fi
print_status "$GREEN" "==========================================="

# Provide minimal version instructions
if [ "$TOTAL_TIME" -gt 60 ]; then
    echo ""
    print_status "$YELLOW" "TIP: For even faster deploys, use:"
    print_status "$YELLOW" "  $0 --quick"
    print_status "$YELLOW" "This skips archive recreation when only updating infrastructure"
fi

echo "Done! Consider switching to student-workshop configuration before testing..."

# Exit successfully
exit 0
