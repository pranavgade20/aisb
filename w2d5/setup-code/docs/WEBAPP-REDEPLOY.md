# CloudAI Portal Rapid Redeploy

Quick reference for rapidly redeploying the CloudAI webapp during development.

## Quick Start

### Standard Redeploy (~45 seconds)
```bash
export PROJECT_ID=your-project-id
./webapp-redeploy.sh
```

### Fast Redeploy (~30 seconds)
```bash
./webapp-redeploy.sh --quick
```


## Scripts Overview

### `webapp-redeploy.sh` - Full Featured Script
- **Purpose**: Production-ready redeploy with error handling and status messages
- **Time**: 30-45 seconds
- **Features**:
  - Color-coded output (RED errors, GREEN success, YELLOW warnings, BLUE info)
  - Timing information for each step
  - Automatic terraform initialization check
  - Portal URL retrieval and display
  - Optional health check
  - Saves URL to `temporary_files/portal_url.txt`

## Command Line Options

### webapp-redeploy.sh Options
- `--quick` - Skip archive recreation (saves ~10-15 seconds)
- `--health-check` - Perform HTTP health check after deployment
- `--help` - Show usage information

## How It Works

The scripts use terraform's `-replace` flag to force recreation of specific resources:

1. **Archive Creation** (data.archive_file.cloudai_portal)
   - Zips the `cloudai-portal/` directory
   - Skipped in `--quick` mode if code hasn't changed

2. **Storage Upload** (google_storage_bucket_object.cloudai_portal_code)
   - Uploads the zip to Cloud Storage bucket
   - Only happens if archive changed

3. **Function Deploy** (google_cloudfunctions2_function.cloudai_portal)
   - Forces replacement with `-replace` flag
   - Ensures fresh deployment every time

4. **IAM Binding** (google_cloud_run_service_iam_member.cloudai_portal_public)
   - Ensures public access is maintained
   - Usually no-op if already configured

## Environment Variables

### Required (one of):
- `PROJECT_ID` - Your GCP project ID
- `TF_VAR_project_id` - Terraform variable for project ID

### Automatically Determined:
- `PROJECT_NUMBER` - Retrieved using gcloud from PROJECT_ID

## Performance Tips

### For Fastest Deploys:
2. Use `--quick` flag when only updating terraform config (not Python code)
3. Keep terraform initialized (`terraform init` already run)
4. Set `PROJECT_ID` in environment to skip prompt

### Typical Timing Breakdown:
- Project configuration: 1-2 seconds
- Terraform init check: 1 second
- Archive creation: 5-10 seconds (skipped with --quick)
- Terraform apply: 25-35 seconds
- URL retrieval: 1 second
- Health check: 5-6 seconds (optional)

## Troubleshooting

### Common Issues:

**"ERROR: PROJECT_ID or TF_VAR_project_id must be set"**
```bash
export PROJECT_ID=your-actual-project-id
```

**"terraform directory not found"**
- Run from repository root, not from terraform/ directory

**"Terraform initialization failed"**
```bash
cd terraform && terraform init
```

**Function deploys but returns 500 error**
- Check Python code in `terraform/cloudai-portal/main.py`
- View logs: `gcloud functions logs read cloudai-portal --limit=50`

**Deployment takes longer than 1 minute**
- Use `--quick` flag if not changing Python code
- Ensure good network connectivity to GCP

## Advanced Usage

### Deploy and Test in One Line
```bash
./webapp-redeploy.sh --health-check && curl -s $(cat temporary_files/portal_url.txt)
```

### Watch Deployment Logs
```bash
# In another terminal:
gcloud functions logs tail cloudai-portal
```

### Force Full Rebuild (rarely needed)
```bash
cd terraform
terraform apply -replace=google_cloudfunctions2_function.cloudai_portal \
                -replace=data.archive_file.cloudai_portal \
                -replace=google_storage_bucket_object.cloudai_portal_code
```

## Portal Code Location

- **Python Code**: `terraform/cloudai-portal/main.py`
- **Requirements**: `terraform/cloudai-portal/requirements.txt`
- **Templates**: `terraform/cloudai-portal/templates/`
- **Static Files**: `terraform/cloudai-portal/static/`

## Integration with Development Workflow

### Typical Development Cycle:
1. Edit Python code in `terraform/cloudai-portal/`
2. Run `./webapp-redeploy.sh`
3. Test at the displayed URL
4. Repeat

### For Template/Static File Changes:
1. Edit files in `templates/` or `static/`
2. Run `./webapp-redeploy.sh` (archive recreation needed)
3. Hard refresh browser (Ctrl+Shift+R)

### For Infrastructure Changes:
1. Edit `terraform/cloudai-portal.tf`
2. Run `./webapp-redeploy.sh --quick` (no archive needed)
3. Verify environment variables or configuration changes

## Security Note

This infrastructure contains intentional vulnerabilities for educational purposes:
- Overprivileged service accounts
- Exposed API keys in environment variables
- Public access without authentication

**NEVER** deploy this to production environments.
