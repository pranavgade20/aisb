## Cloud Security Course Structure for AI Researchers

### Key Modifications:
- **Remove Challenge 1 & 2** (Kubernetes-dependent)
- **Start with Module 2** as intro (terraform state exposure)
- **Focus on Modules 2, 3, 4** with simplified setup
- **Add new simplified scenarios** for missing concepts

### Proposed 4-Module Structure:

#### **Module 1: Environment Secrets & State Exposure**
- **Attack Lab**: Modified Module 2
  - Find exposed terraform state in public bucket
  - Extract SSH keys and infrastructure details
  - Simple webapp deployment instead of complex infra
- **Remediation Lab**: 
  - Secure state storage
  - Secret rotation
  - Principle of least privilege for buckets

#### **Module 2: Instance Metadata Service (IMDS) Exploitation**
- **Attack Lab**: Module 3 (simplified)
  - Access VM via SSH from Module 1
  - Discover cloud function with SSRF vulnerability
  - Extract service account token via metadata endpoint
- **Remediation Lab**:
  - IMDSv2 configuration
  - Network policies
  - Input validation for cloud functions

#### **Module 3: Service Account Misconfigurations**
- **Attack Lab**: Challenge 5
  - Use token from Module 2
  - Discover privilege escalation via impersonation
  - Achieve project-level access
- **Remediation Lab**:
  - Service account key rotation
  - Workload identity
  - IAM best practices

#### **Module 4: Enumeration & Discovery** (New)
- **Attack Lab**: New simplified scenario
  - Public storage bucket enumeration
  - Finding dev/staging/prod patterns
  - API endpoint discovery
- **Remediation Lab**:
  - Bucket naming conventions
  - Access logging
  - Resource tagging

### Additional Simplifications:
- Remove GKE cluster entirely
- Use only Cloud Functions, VMs, and Storage
- Provide pre-configured gcloud CLI access
- Include visual diagrams for each attack path
- Add "What this means for AI/ML workloads" section per module