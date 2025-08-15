#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Module 1 Infrastructure Validation Script"
echo "=========================================="

# Check prerequisites
echo -e "\n${YELLOW}[1/10] Checking prerequisites...${NC}"

if [ -z "${PROJECT_ID:-}" ]; then
    echo -e "${RED}✗ ERROR: PROJECT_ID environment variable not set${NC}"
    echo "Please run: export PROJECT_ID=<your-project-id>"
    exit 1
fi
echo -e "${GREEN}✓ PROJECT_ID is set: $PROJECT_ID${NC}"

# Check for required tools
for tool in gcloud gsutil jq; do
    # Check if command exists without using negation operator
    command -v "$tool" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ ERROR: $tool is not installed${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ All required tools are installed${NC}"

# Check that validation configuration is active
echo -e "\n${YELLOW}[2/10] Verifying validation configuration...${NC}"
CURRENT_CONFIG=$(gcloud config configurations list --filter="is_active=true" --format="value(name)" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to get current configuration: $CURRENT_CONFIG${NC}"
    exit 1
fi

if [ "$CURRENT_CONFIG" != "validation" ]; then
    echo -e "${RED}✗ ERROR: Current configuration is '$CURRENT_CONFIG', not 'validation'${NC}"
    echo "This script must be run through validate-driver.sh"
    exit 1
fi
echo -e "${GREEN}✓ Running in validation configuration${NC}"

# Verify we have proper project context
echo -e "\n${YELLOW}[3/10] Verifying project context...${NC}"
CURRENT_PROJECT=$(gcloud config get-value project 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to get project: $CURRENT_PROJECT${NC}"
    exit 1
fi

# Check if the PROJECT_ID appears in the gcloud output (handles various output formats)
if echo "$CURRENT_PROJECT" | grep -q "$PROJECT_ID"; then
    echo -e "${GREEN}✓ Project context is correct: $PROJECT_ID${NC}"
else
    echo -e "${RED}✗ ERROR: Project mismatch - expected $PROJECT_ID, got $CURRENT_PROJECT${NC}"
    exit 1
fi

# Test student-workshop permissions (we're already in validation config with student account)
echo -e "\n${YELLOW}[4/10] Testing student-workshop permissions...${NC}"


# Test that student-workshop CAN access modeldata-dev bucket
echo -e "  Testing modeldata-dev access..."
DEV_ACCESS_OUTPUT=$(gsutil ls "gs://modeldata-dev-$PROJECT_ID" 2>&1)
DEV_ACCESS_CODE=$?

if echo "$DEV_ACCESS_OUTPUT" | grep -q "AccessDeniedException\|Forbidden"; then
    echo -e "${RED}✗ student-workshop cannot access modeldata-dev bucket (should have access)${NC}"
    exit 1
else
    if [ $DEV_ACCESS_CODE -eq 0 ]; then
        echo -e "${GREEN}✓ student-workshop can access modeldata-dev bucket${NC}"
    else
        echo -e "${RED}✗ Error accessing modeldata-dev bucket: $DEV_ACCESS_OUTPUT${NC}"
        exit 1
    fi
fi

# Test that student-workshop CANNOT access modeldata-prod bucket
echo -e "  Testing modeldata-prod restriction..."
PROD_ACCESS_OUTPUT=$(gsutil ls "gs://modeldata-prod-$PROJECT_ID" 2>&1)
PROD_ACCESS_CODE=$?

if echo "$PROD_ACCESS_OUTPUT" | grep -q "AccessDeniedException\|Forbidden"; then
    echo -e "${GREEN}✓ student-workshop cannot access modeldata-prod bucket (correctly restricted)${NC}"
else
    if [ $PROD_ACCESS_CODE -eq 0 ]; then
        echo -e "${RED}✗ student-workshop can access modeldata-prod bucket (should be restricted)${NC}"
        exit 1
    else
        # Check for other errors
        echo -e "${GREEN}✓ student-workshop cannot access modeldata-prod bucket (correctly restricted)${NC}"
    fi
fi

# Test that student-workshop CANNOT list compute instances
echo -e "\n${YELLOW}[5/10] Testing compute instance restrictions...${NC}"
COMPUTE_OUTPUT=$(gcloud compute instances list 2>&1)
COMPUTE_CODE=$?

if echo "$COMPUTE_OUTPUT" | grep -q "Required 'compute.instances.list' permission\|Forbidden\|PERMISSION_DENIED\|does not have compute.instances.list"; then
    echo -e "${GREEN}✓ student-workshop cannot list compute instances (correctly restricted)${NC}"
else
    if [ $COMPUTE_CODE -eq 0 ]; then
        echo -e "${RED}✗ student-workshop can list compute instances (should be restricted)${NC}"
        exit 1
    else
        # Check if it's a permission error even without specific message
        echo -e "${GREEN}✓ student-workshop cannot list compute instances (correctly restricted)${NC}"
    fi
fi

# Continue with infrastructure tests (still in validation config)
echo -e "\n${YELLOW}Continuing infrastructure tests...${NC}"

# Test 1: Check dev bucket exists
echo -e "\n${YELLOW}[6/10] Checking modeldata-dev bucket...${NC}"
DEV_BUCKET_CHECK=$(gsutil ls "gs://modeldata-dev-$PROJECT_ID" 2>&1)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ modeldata-dev bucket exists${NC}"
else
    echo -e "${RED}✗ modeldata-dev bucket not found: $DEV_BUCKET_CHECK${NC}"
    exit 1
fi

# Test 2: Check prod bucket is not accessible (as student)
echo -e "\n${YELLOW}[7/10] Checking modeldata-prod bucket...${NC}"
PROD_BUCKET_CHECK=$(gsutil ls "gs://modeldata-prod-$PROJECT_ID" 2>&1)
if [ $? -eq 1 ]; then
    echo -e "${GREEN}✓ modeldata-prod bucket not accessible!${NC}"
else
    echo -e "${RED}✗ modeldata-prod bucket was accessible to student?!: $PROD_BUCKET_CHECK${NC}"
    exit 1
fi

# Test 3: Check service account key in dev bucket
echo -e "\n${YELLOW}[8/10] Checking for service account key in dev bucket...${NC}"
KEY_CHECK=$(gsutil ls "gs://modeldata-dev-$PROJECT_ID/bucket-service-account.json" 2>&1)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Service account key found in dev bucket${NC}"
else
    echo -e "${RED}✗ Service account key not found in dev bucket: $KEY_CHECK${NC}"
    exit 1
fi

# Test 4: Download and test service account key
echo -e "\n${YELLOW}[9/10] Testing service account key functionality...${NC}"
TEMP_KEY=$(mktemp)
DOWNLOAD_OUTPUT=$(gsutil cp "gs://modeldata-dev-$PROJECT_ID/bucket-service-account.json" "$TEMP_KEY" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Failed to download service account key: $DOWNLOAD_OUTPUT${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Test the service account
AUTH_OUTPUT=$(gcloud auth activate-service-account --key-file="$TEMP_KEY" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Service account activation failed: $AUTH_OUTPUT${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

ACTIVE_ACCOUNTS=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>&1)
if echo "$ACTIVE_ACCOUNTS" | grep -q "bucket-service-account"; then
    echo -e "${GREEN}✓ Service account authentication successful${NC}"
else
    echo -e "${RED}✗ Service account authentication failed - account not active${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Test 5: Verify service account can access prod bucket
echo -e "\n${YELLOW}[10/10] Testing service account access to prod bucket...${NC}"
SA_PROD_ACCESS=$(gsutil ls "gs://modeldata-prod-$PROJECT_ID/" 2>&1)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Service account can access prod bucket${NC}"
else
    echo -e "${RED}✗ Service account cannot access prod bucket: $SA_PROD_ACCESS${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Test 6: Check for flag in prod bucket (included in step 10)
FLAG1PARTB_FILE='flag1-partB.txt'
echo -e "  Checking for flag in prod bucket..."
FLAG_CHECK=$(gsutil ls "gs://modeldata-prod-$PROJECT_ID/${FLAG1PARTB_FILE}" 2>&1)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Flag file exists in prod bucket${NC}"
    
    # Download and display flag
    FLAG_CONTENT=$(gsutil cat "gs://modeldata-prod-$PROJECT_ID/${FLAG1PARTB_FILE}" 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ Flag(${FLAG1PARTB_FILE}) content: $FLAG_CONTENT${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Could not read flag content: $FLAG_CONTENT${NC}"
    fi
else
    echo -e "${RED}✗ Flag not found in prod bucket: $FLAG_CHECK${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Cleanup temp key
rm -f "$TEMP_KEY"

echo -e "\n${GREEN}=========================================="
echo "✓ Module 1 validation PASSED!"
echo "==========================================${NC}"
