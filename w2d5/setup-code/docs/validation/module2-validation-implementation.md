# Module 2 Validation Script Implementation

## Overview
Created an automated validation script (`validate-m2.sh`) for Module 2 of the GCP AI Security Lab CTF workshop to ensure infrastructure is correctly configured and exploitable via the intended path.

## Key Implementation Details

### Script Purpose
- Validates that Module 2's intentionally vulnerable infrastructure is properly deployed
- Tests the complete exploit chain to ensure CTF participants can follow the intended path
- Provides clear pass/fail indicators for each validation step
- Enables quick infrastructure validation after setup or reset

### Exploit Path Validated
1. **Bucket Access**: Verifies `gs://file-uploads-$PROJECT_ID` bucket exists and is accessible
2. **State File Exposure**: Confirms terraform state file (`infrastructure_config.tfstate`) is present in bucket
3. **Secret Extraction**: Validates that SSH private key can be extracted from state file's Secret Manager resource
4. **VM Access**: Tests SSH connectivity to compute instance using extracted credentials
5. **Flag Verification**: Confirms `flag1.txt` exists in alice's home directory

### Technical Components
- **Dependencies**: Requires `gcloud`, `gsutil`, `jq`, `ssh`, `base64` commands
- **JSON Parsing**: Uses `jq` to extract specific resource attributes from terraform state
- **Error Handling**: Implements proper error checking with colored output (red/green/yellow)
- **Cleanup**: Uses temporary directory with automatic cleanup on exit
- **Security**: Sets proper permissions (600) on extracted SSH key

### Infrastructure Elements Validated
- Google Cloud Storage bucket with public terraform state file
- Secret Manager resource containing base64-encoded SSH private key
- Compute instance with external IP and alice user configured
- Service account configuration on VM
- Challenge 4 preparation files (`invoke_monitoring_function.sh`)

### Usage
```bash
export PROJECT_ID=<your-project-id>
./validate-m2.sh
```

### Exit Codes
- `0`: All validations passed
- `1`: Validation failure (with specific error message)

## Future Improvements
- Add parallel validation for multiple modules
- Include performance benchmarks
- Add option to fix common setup issues automatically
- Integrate with CI/CD for automated testing
