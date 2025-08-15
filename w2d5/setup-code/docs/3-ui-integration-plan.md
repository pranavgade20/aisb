# CloudAI Labs Security Bootcamp: Module Overview & UI Integration Plan

## Project Context
CloudAI Labs is a fictional ML model hosting platform used to teach GCP security through hands-on exploitation. Students progress through 4 modules, each building on discoveries from the previous one.

## Learning Modules Overview

### Module 1: Public Bucket Exposure
**Scenario:** CloudAI Labs' dev bucket exposed, containing "leaked GPT-6 benchmarks"  
**Skills:** Cloud storage enumeration, service account compromise  
**Infrastructure:** 
- Dev bucket: `modeldata-dev-[PROJECT_ID]` (public read)
- Prod bucket: `modeldata-prod-[PROJECT_ID]` (requires auth)
**Key Files:** 
- `flag1_gpt5_benchmarks.txt` (first flag)
- `bucket-service-account.json` (leads to Module 2)
**Setup Script:** `mod1-setup.sh`

### Module 2: Infrastructure as Code Secrets  
**Scenario:** Production bucket contains terraform state with SSH keys  
**Skills:** State file analysis, SSH key extraction, lateral movement  
**Infrastructure:**
- Compute instance: `app-prod-instance-module2`
- SSH user: `alice`
**Key Files:** 
- `terraform.tfstate` in prod bucket
- Encoded SSH private key in state file
**Setup Script:** `mod2-setup.sh`

### Module 3: Metadata Service Exploitation
**Scenario:** Monitoring function vulnerable to SSRF attacks  
**Skills:** SSRF exploitation, metadata service abuse, token theft  
**Infrastructure:**
- Cloud Function: `monitoring-function`
- Vulnerable endpoint accepts `metadata` parameter
**Exploit:** 
```bash
curl -X POST [FUNCTION_URL] -d '{"metadata":"token"}'
```
**Key Discovery:** Function's service account token

### Module 4: IAM Privilege Escalation
**Scenario:** Compromised account can impersonate terraform pipeline  
**Skills:** IAM analysis, service account impersonation, persistence  
**Infrastructure:**
- Service Account: `terraform-pipeline`
- Custom Role: `TerraformPipelineProjectAdmin`
**Goal:** Add personal Google account to project using impersonation

## Web Portal Integration

### Architecture
Single Cloud Function (`cloudai-portal`) with routes:
- `/` - Homepage
- `/docs` - Developer documentation (Module 1)
- `/status` - Deployment status (Module 2)
- `/monitoring` - Monitoring dashboard (Module 3)
- `/admin` - Admin console (Module 4)
- `/api/v1/*` - Model inference API

### Module-Specific Web Features

#### Module 1: Documentation Information Disclosure
**URL:** `/docs`  
**Vulnerability:** Hardcoded bucket names in example code  
**Implementation:**
```python
# Shows bucket names directly in HTML
example_code = """
# Upload your model:
gsutil cp model.pkl gs://modeldata-dev-{PROJECT_ID}/

# Production models (restricted):
gs://modeldata-prod-{PROJECT_ID}/
"""
```
**Student Flow:** Visit docs → Copy bucket name → Use gsutil to explore

#### Module 2: Status Page Path Traversal
**URL:** `/status`  
**Vulnerability:** Direct links to sensitive files  
**Implementation:**
```python
# Status page shows deployment artifacts
deployments = [{
    'timestamp': '2024-01-15',
    'artifacts': {
        'state': f'https://storage.googleapis.com/modeldata-prod-{PROJECT_ID}/terraform.tfstate'
    }
}]
```
**Student Flow:** Access prod bucket (Module 1 creds) → Click tfstate link → Download and decode SSH key

#### Module 3: SSRF via Monitoring Form
**URL:** `/monitoring`  
**Vulnerability:** User-controlled metadata endpoint parameter  
**Implementation:**
```python
@app.route('/monitoring/check', methods=['POST'])
def check():
    # SSRF: User controls 'endpoint' parameter
    endpoint = request.form.get('endpoint', 'email')
    
    # Calls vulnerable monitoring function
    response = call_monitoring_function({'metadata': endpoint})
    
    # Returns raw response including tokens
    return jsonify(response)
```
**Web Form:**
```html
<form method="POST" action="/monitoring/check">
    <select name="endpoint">
        <option value="email">Service Account Email</option>
        <option value="token">Access Token (Debug)</option>
    </select>
    <button>Check Status</button>
</form>
```
**Student Flow:** SSH to VM → Find monitoring URL → Select "token" option → Copy token from response

#### Module 4: Admin Console with Token Validation
**URL:** `/admin`  
**Vulnerability:** Token accepted via Authorization header or form  
**Implementation:**
```python
@app.route('/admin')
def admin():
    # Check for token from Module 3
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        # Show login form with hint
        return render_template('admin_login.html', 
            hint='Use the token from monitoring function')
    
    # Validate token and show IAM details
    try:
        service_accounts = list_service_accounts(token)
        return render_template('admin_panel.html', 
            accounts=service_accounts,
            can_impersonate=check_impersonation_permissions(token))
    except:
        return "Invalid token", 401
```
**Student Flow:** Use Module 3 token → Access admin panel → See terraform-pipeline account → Test impersonation

### Implementation Phases

**Phase 1:** Basic portal with docs and API  
**Phase 2:** Status page and monitoring dashboard  
**Phase 3:** Admin console with IAM explorer

### Key Benefits
- Browser + terminal paths for each module
- Visual learning for complex concepts (IAM, tokens)
- Realistic cloud platform experience
- No changes to existing infrastructure

### Setup Flow
1. Deploy existing terraform infrastructure
2. Run module setup scripts
3. Deploy portal Cloud Function
4. Students access via browser or terminal