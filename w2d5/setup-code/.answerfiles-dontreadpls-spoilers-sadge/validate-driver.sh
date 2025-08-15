#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Module 1, 2 & 3 Validation Driver Script"
echo "=========================================="

# Check PROJECT_ID is set
if [ -z "${PROJECT_ID:-}" ]; then
    echo -e "${RED}✗ ERROR: PROJECT_ID environment variable not set${NC}"
    echo "Please run: export PROJECT_ID=<your-project-id>"
    exit 1
fi

# Create shared validation test directory at the start
echo -e "\n${YELLOW}[0/9] Creating validation test directory...${NC}"
VAL_TEST_DIR="./val-test"
mkdir -p "$VAL_TEST_DIR"
echo -e "${GREEN}✓ Created/using validation test directory: $VAL_TEST_DIR${NC}"

# Step 1: Verify student-workshop config is active
echo -e "\n${YELLOW}[1/6] Verifying current configuration...${NC}"
CURRENT_CONFIG=$(gcloud config configurations list --filter="is_active=true" --format="value(name)" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to get current configuration: $CURRENT_CONFIG${NC}"
    exit 1
fi

if [ "$CURRENT_CONFIG" != "student-workshop" ]; then
    echo -e "${RED}✗ ERROR: Current configuration is '$CURRENT_CONFIG', not 'student-workshop'${NC}"
    echo "Please activate student-workshop configuration first:"
    echo "  gcloud config configurations activate student-workshop"
    exit 1
fi
echo -e "${GREEN}✓ student-workshop configuration is active${NC}"

# Step 2: Save original configuration details
echo -e "\n${YELLOW}[2/6] Saving original configuration details...${NC}"
ORIGINAL_ACCOUNT=$(gcloud config get-value account 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to get account from student-workshop: $ORIGINAL_ACCOUNT${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Account saved: $ORIGINAL_ACCOUNT${NC}"

# Step 3: Create temporary validation configuration
echo -e "\n${YELLOW}[3/6] Creating validation configuration...${NC}"

# Check if validation config already exists and delete it
if gcloud config configurations list --format="value(name)" 2>/dev/null | grep -q "^validation$"; then
    echo -e "  ${YELLOW}Removing existing validation configuration...${NC}"
    DELETE_OUTPUT=$(gcloud config configurations delete validation --quiet 2>&1)
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ ERROR: Failed to delete existing validation config: $DELETE_OUTPUT${NC}"
        exit 1
    fi
fi

# Create new validation configuration
CREATE_OUTPUT=$(gcloud config configurations create validation 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to create validation configuration: $CREATE_OUTPUT${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Created validation configuration${NC}"

# Configure validation with account and project
echo -e "  Setting account..."
SET_ACCOUNT_OUTPUT=$(gcloud config set account "student-workshop@${PROJECT_ID}.iam.gserviceaccount.com" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to set account: $SET_ACCOUNT_OUTPUT${NC}"
    # Cleanup on failure
    gcloud config configurations activate student-workshop 2>/dev/null
    gcloud config configurations delete validation --quiet 2>/dev/null
    exit 1
fi

echo -e "  Setting project..."
SET_PROJECT_OUTPUT=$(gcloud config set project "$PROJECT_ID" 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ERROR: Failed to set project: $SET_PROJECT_OUTPUT${NC}"
    # Cleanup on failure
    gcloud config configurations activate student-workshop 2>/dev/null
    gcloud config configurations delete validation --quiet 2>/dev/null
    exit 1
fi
echo -e "${GREEN}✓ Validation configuration ready${NC}"

# Step 4: Run validation script
echo -e "\n${YELLOW}[4/6] Running validation tests...${NC}"
echo "=========================================="

# Run validate-m1.sh and capture exit code
./validate-m1.sh
VALIDATION_EXIT_CODE=$?

echo "=========================================="

# Step 4b: Run Module 2 validation
echo -e "\n${YELLOW}[4b/8] Running Module 2 validation tests...${NC}"
echo "=========================================="

# Run validate-m2.sh and capture exit code
./validate-m2.sh
MODULE2_EXIT_CODE=$?

echo "=========================================="

# Step 4c: Run Module 3 validation in validation config
echo -e "\n${YELLOW}[4c/9] Running Module 3 validation tests...${NC}"
echo "=========================================="

# Ensure we have LOCATION set for Module 3
export LOCATION="us-east1"

# Run validate-m3.sh and capture exit code
./validate-m3.sh
MODULE3_EXIT_CODE=$?

echo "=========================================="

# Step 4d: Run Module 4 validation in validation config
echo -e "\n${YELLOW}[4d/9] Running Module 4 / Chal5 validation tests...${NC}"
echo "=========================================="

./validate-c5.sh
MODULE4_EXIT_CODE=$?

echo "=========================================="

# Combine exit codes (fail if any failed)
if [ $VALIDATION_EXIT_CODE -ne 0 ] || [ $MODULE2_EXIT_CODE -ne 0 ] || [ $MODULE3_EXIT_CODE -ne 0 ] || [ $MODULE4_EXIT_CODE -ne 0 ] ; then
    COMBINED_EXIT_CODE=1
else
    COMBINED_EXIT_CODE=0
fi

# Step 5: Restore original configuration
echo -e "\n${YELLOW}[5/9] Restoring original configuration...${NC}"
RESTORE_OUTPUT=$(gcloud config configurations activate student-workshop 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Warning: Failed to restore student-workshop: $RESTORE_OUTPUT${NC}"
    echo "  You may need to manually activate it:"
    echo "  gcloud config configurations activate student-workshop"
else
    echo -e "${GREEN}✓ Restored student-workshop configuration${NC}"
fi

# Step 6: Clean up validation configuration
echo -e "\n${YELLOW}[6/9] Cleaning up validation configuration...${NC}"
DELETE_OUTPUT=$(gcloud config configurations delete validation --quiet 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Warning: Failed to delete validation config: $DELETE_OUTPUT${NC}"
    echo "  You may need to manually delete it:"
    echo "  gcloud config configurations delete validation"
else
    echo -e "${GREEN}✓ Deleted validation configuration${NC}"
fi

# Step 7: Clean up bucket-service-account.json if it exists
echo -e "\n${YELLOW}[7/9] Cleaning up temporary files...${NC}"
if [ -f "./bucket-service-account.json" ]; then
    rm -f ./bucket-service-account.json
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Deleted bucket-service-account.json file${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Failed to delete bucket-service-account.json${NC}"
        echo "  You may need to manually delete it:"
        echo "  rm ./bucket-service-account.json"
    fi
else
    echo -e "${YELLOW}ℹ No bucket-service-account.json file found to clean up${NC}"
fi

# Step 8: Clean up validation test directory
echo -e "\n${YELLOW}[8/9] Cleaning up validation test directory...${NC}"
if [ -d "$VAL_TEST_DIR" ]; then
    rm -rf "$VAL_TEST_DIR"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Deleted validation test directory${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Failed to delete validation test directory${NC}"
        echo "  You may need to manually delete it:"
        echo "  rm -rf $VAL_TEST_DIR"
    fi
else
    echo -e "${YELLOW}ℹ No validation test directory found to clean up${NC}"
fi

# Exit with combined code from all validation scripts
if [ ${COMBINED_EXIT_CODE:-$VALIDATION_EXIT_CODE} -eq 0 ]; then
    echo -e "\n${GREEN}=========================================="
    echo "✓ All validations completed successfully!"
    echo "  - Module 1: PASSED"
    echo "  - Module 2: PASSED"
    echo "  - Module 3: PASSED"
    echo "  - Module 4: PASSED"
    echo "==========================================${NC}"
else
    echo -e "\n${RED}=========================================="
    echo "✗ Validation failed"
    
    # Module 1 status
    if [ $VALIDATION_EXIT_CODE -ne 0 ]; then
        echo "  - Module 1: FAILED"
    else
        echo "  - Module 1: PASSED"
    fi
    
    # Module 2 status
    if [ ${MODULE2_EXIT_CODE:-0} -ne 0 ]; then
        echo "  - Module 2: FAILED"
    else
        echo "  - Module 2: PASSED"
    fi
    
    # Module 3 status
    if [ ${MODULE3_EXIT_CODE:-0} -ne 0 ]; then
        echo "  - Module 3: FAILED"
    else
        echo "  - Module 3: PASSED"
    fi
    

    # Module 4 status
    if [ ${MODULE4_EXIT_CODE:-0} -ne 0 ]; then
        echo "  - Module 4: FAILED"
    else
        echo "  - Module 4: PASSED"
    fi
    
    echo "==========================================${NC}"
fi

exit ${COMBINED_EXIT_CODE:-$VALIDATION_EXIT_CODE}
