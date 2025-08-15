# Insecure Model Hosting Platform - Implementation Plan

## Overview
This project creates an intentionally insecure model hosting platform similar to Hugging Face, deployed on Google Cloud Platform with multiple security vulnerabilities. The goal is to provide hands-on experience with cloud security exploitation and remediation.

## Architecture Overview

### Initial Attack Vector: Pickle Deserialization
- Users upload ML models (pickle files) that get deserialized on the server
- Malicious pickle payloads allow remote code execution
- Once inside, attackers can exploit various GCP misconfigurations

### Target Platform: Model Hosting Website
- Web interface for uploading/downloading ML models
- Model inference API endpoints
- User management system
- Model versioning and storage

## Phase 1: Infrastructure Setup (Terraform)

### 1.1 Project Configuration
- Create new GCP project intentionally misconfigured minimal security
- Enable all APIs without proper IAM controls
- Disable security features and logging

### 1.2 Storage Vulnerabilities
- **Public Storage Buckets**
  - Create a public bucket for model storage
  - No versioning or deletion protection
  - Bucket paths follow predictable patterns
  - so the user can get secret-model/model.pt from another org

- **Database Misconfigurations**
  - Cloud SQL instance with public IP
  - Default credentials (admin/admin)
  - No SSL/TLS enforcement
  - No backup encryption

### 1.3 Compute Vulnerabilities
- **VM Instances**
  - Instances with public IPs and default service accounts
  - No firewall rules or network security
  - Instance metadata service enabled with default settings
  - no OS Login
  - No disk encryption

### 1.4 Identity & Access Management Issues
- **Service Account Misconfigurations**
  - Service account with Owner role
  - Long-lived access keys stored in plaintext
    - the fix to this should be setting up google secrets manager
  - No rotation policies
  - Keys embedded in code and configuration files

- **IAM Vulnerabilities**
  - Overly permissive roles assigned
  - No principle of least privilege
  - Service accounts with multiple roles
  - No conditional access policies

### 1.5 API & Application Vulnerabilities
- **Cloud Functions/Lambda**
  - Functions without authentication
  - No input validation
  - Secrets stored in environment variables
  - No rate limiting

- **API Gateway**
  - No authentication required
  - CORS misconfigured
  - No request validation
  - Logging disabled

### 1.6 Monitoring & Logging Issues
- **Logging Disabled**
  - Cloud Audit Logs disabled
  - No centralized logging
  - Application logs not captured
  - No alerting configured

- **Monitoring Gaps**
  - No security monitoring
  - No anomaly detection
  - No real-time alerts
  - Metrics collection disabled

## Phase 2: Application Vulnerabilities

### 2.1 Web Application Security Issues
- **Authentication Bypass**
  - SQL injection vulnerabilities
  - No input sanitization
  - Session management flaws
  - CSRF protection disabled

- **File Upload Vulnerabilities**
  - No file type validation
  - No size limits
  - Direct file execution
  - Path traversal vulnerabilities

### 2.2 Pickle Deserialization Attack
- **Model Upload Endpoint**
  - Accepts pickle files without validation
  - Deserializes user input directly
  - No sandboxing or isolation
  - Root privileges for model execution

### 2.3 Secrets Management
- **Hardcoded Secrets**
  - Database credentials in code
  - API keys in environment variables
  - Private keys in configuration files
  - No secret rotation

## Phase 3: Exploitation Labs

### Lab 1: Initial Access via Pickle Deserialization
**Objective**: Gain initial access through malicious pickle file
**Steps**:
1. Create malicious pickle payload
2. Upload as "model" through web interface
3. Trigger model execution
4. Establish reverse shell
    - or just copy ssh key to .ssh/authorized_keys

**Learning**: Understanding deserialization attacks and input validation

### Lab 2: Instance Metadata Service Exploitation
**Objective**: Extract service account tokens and metadata
**Steps**:
1. Access instance metadata service
2. Extract service account tokens
3. Use tokens to access GCP APIs
4. Enumerate project resources

**Learning**: Understanding IMDS security and token management

### Lab 3: Storage Bucket Enumeration
**Objective**: Access sensitive data in public buckets
**Steps**:
1. Discover bucket names
2. List bucket contents
3. Download files from other users
4. Access backup data

**Learning**: Understanding bucket security and data exposure

### Lab 4: Database Exploitation
**Objective**: Access and exfiltrate database data
**Steps**:
1. Connect to public database
2. Extract user credentials
3. Access sensitive data
4. Perform privilege escalation

**Learning**: Understanding database security and access controls

### Lab 5: Service Account Privilege Escalation
**Objective**: Leverage excessive permissions
**Steps**:
1. Use service account credentials
2. Create additional resources
3. Modify IAM policies
4. Establish persistence

**Learning**: Understanding IAM security and least privilege

### Lab 6: Secrets Exfiltration
**Objective**: Extract hardcoded secrets
**Steps**:
1. Search for secrets in code
2. Access environment variables
3. Extract API keys and tokens
4. Use secrets for lateral movement

**Learning**: Understanding secrets management and secure coding

## Phase 4: Remediation Labs

### Remediation 1: Secure Pickle Deserialization
**Fix**: Implement secure model loading
- Use alternative serialization formats (.safetensors)
- Implement model validation and signing (optional)
- Add sandboxing and isolation (optional)

### Remediation 2: Secure Instance Configuration
**Fix**: Harden compute instances
- Disable instance metadata service
- Use private IPs only
- Implement proper firewall rules
- Enable OS Login
- Use minimal service accounts

### Remediation 3: Secure Storage Configuration
**Fix**: Implement proper bucket security
- Make buckets private
- Enable encryption at rest
- Implement proper IAM policies
- Enable versioning and deletion protection
- Use signed URLs for access

### Remediation 4: Database Security
**Fix**: Secure database access
- Use private IPs only
- Implement proper authentication
- Enable SSL/TLS
- Use connection pooling
- Implement proper backup encryption

### Remediation 5: IAM Security
**Fix**: Implement least privilege access
- Remove excessive permissions
- Use custom roles
- Implement conditional access
- Enable audit logging
- Regular access reviews

### Remediation 6: Secrets Management
**Fix**: Implement proper secrets management
- Use Secret Manager
- Implement secret rotation
- Remove hardcoded secrets
- Use workload identity
- Implement proper access controls

### Remediation 7: API Security
**Fix**: Secure API endpoints
- Implement proper authentication
- Add input validation
- Enable rate limiting
- Implement proper logging
- Use API keys and OAuth

### Remediation 8: Monitoring and Logging
**Fix**: Implement comprehensive monitoring
- Enable Cloud Audit Logs
- Implement centralized logging
- Set up security monitoring
- Configure real-time alerts
- Implement anomaly detection

## Phase 5: Terraform Implementation

### 5.1 Infrastructure as Code Structure
- terraform folder with the files to set up the vulnerable application
- app folder that contains the source code that will be copied to the compute engine instance


### 5.2 Terraform State Management
- Store state in public S3 bucket (vulnerability)
- Include secrets in state files
- No state encryption
- No access controls on state

### 5.3 Terraform Vulnerabilities
- Hardcoded credentials in variables
- No backend encryption
- Public state storage
- No state locking
- Secrets in plaintext

## Phase 6: Website Implementation

### 6.1 Technology Stack
- **Frontend**: Simple js + HTML page
- **Backend**: Python Flask with security issues
- **Database**: Cloud SQL with misconfigurations
- **Storage**: Cloud Storage with public access
- **Compute**: Compute engine with excessive permissions

### 6.2 Application Features
- User registration and authentication
- Model upload and download
- Model inference API
- User dashboard
- Model versioning

## Phase 7: Documentation and Guides

### 7.1 Student Guide
- A high-level explainer about what the goal is
    - Step-by-step exploitation instructions that can be hints if they don't get it from the high-level instructions
    - followed by a list of all the things that should be fixed
    - followed by how to fix them
- Expected outcomes and learning objectives
- Troubleshooting guide
- Additional resources

### 7.2 Instructor Guide
- Setup instructions
- Solution walkthroughs
- Extension activities
