## Module 3 Implementation & Validation - Comprehensive Overview

### Core Architecture
• **SSRF Vulnerability**: Cloud Function (Gen2) accepts user-controlled `metadata` parameter, queries GCP metadata server with user input, returns flag4 when `metadata: "token"` requested
• **Privilege Escalation Path**: VM has limited OAuth scope (devstorage.read_only) → Function has full cloud-platform scope (editor role) → Extract function's service account token via SSRF
• **Gen2 Functions**: Deploy as Cloud Run services with URLs like `https://{name}-{hash}-{region}.a.run.app`, require identity tokens (not access tokens)

### Critical Issues Fixed

#### 1. Function URL Portability
• **Problem**: Hardcoded function URL in `invoke_monitoring_function.sh` broke across different GCP projects
• **Fix**: Dynamic URL retrieval using `gcloud run services describe monitoring-function --region=$LOCATION --format='value(status.url)'`
• **Key Learning**: Always use dynamic service discovery for cloud resources instead of hardcoding URLs

#### 2. Permission Catch-22
• **Problem**: VM's limited service account can't run `gcloud run services describe` but needs the function URL
• **Fix**: Save function URL to `/home/alice/.function_url` during setup via `challenge-setup.sh`
• **Key Learning**: When designing CTF challenges, ensure participants have a path to needed resources despite intentional permission limitations

#### 3. Validation Script Output Parsing
• **Problem**: `exec_on_vm()` used `2>&1` redirection, mixing stderr status messages with stdout JSON output
• **Fix**: Redirect stderr to temp file, only show on error: `output=$(gcloud compute ssh ... 2>"$stderr_file")`
• **Key Learning**: Always separate stderr from stdout when parsing command output, especially for JSON responses

#### 4. OAuth Scope vs IAM Role Confusion
• **Problem**: VM created with limited OAuth scope (`devstorage.read_only`) that cannot be expanded via IAM roles
• **Fix**: Understand that OAuth scopes are immutable at VM creation time - IAM roles alone cannot grant additional API access
• **Key Learning**: OAuth scopes set hard limits on VM capabilities regardless of IAM permissions

#### 5. Gen2 Cloud Functions Authentication
• **Problem**: Gen1 authentication patterns failed (wrong IAM role, incorrect token type)
• **Fix**: Use `roles/run.invoker` (not `cloudfunctions.invoker`), case-sensitive "Bearer" header, identity tokens
• **Key Learning**: Gen2 functions are Cloud Run services with different auth requirements than Gen1

#### 6. Nested JSON Token Extraction
• **Problem**: Function returns nested escaped JSON in `function_account` field, initial script requested wrong metadata
• **Fix**: Request `metadata: "token"` (not "email"), implement robust JSON unescaping: `sed 's/\\\"/"/g'`
• **Key Learning**: Always verify API response structure before parsing, consider using `jq` for complex JSON

### Educational Design Insights
• **Two-Stage Deployment**: Terraform creates infrastructure → `challenge-setup.sh` uploads `main.py` separately (ensures function source is accessible from VM)
• **Permission Demonstration**: VM can't directly get function URL, teaching about GCP IAM limitations while providing workaround via saved file
• **Real-World Pattern**: The `.function_url` approach mirrors how credentials/endpoints are often shared in restricted environments

### Validated Attack Path
1. SSH to VM with limited OAuth scopes
2. Read function source from storage bucket (allowed by scope)
3. Discover SSRF vulnerability in monitoring function
4. Exploit SSRF to extract function's service account token
5. Use elevated token (cloud-platform scope) for privilege escalation

### Quick Reference for Future Issues
• **Gen2 Function Won't Invoke**: Check for identity token (not access token), verify Cloud Run URL format, ensure "Bearer" capitalization
• **Validation Fails on Output Parsing**: Ensure stderr/stdout separation in scripts, handle nested/escaped JSON properly
• **Permission Errors on VM**: Pre-save needed resources during setup rather than expecting dynamic discovery
• **OAuth Scope Limitations**: Remember scopes are set at VM creation and cannot be expanded - design around this constraint
• **Error Masking**: Remove `|| true` patterns that hide failures during debugging

### Final Validation Status
• All 24 validation checks passing
• Infrastructure correctly demonstrates intended SSRF vulnerability
• Ready for CTF deployment with proper educational value