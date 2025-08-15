# CloudAI Portal Implementation Summary

## Project Overview
Transformed a GCP security CTF into an AI-focused security bootcamp by implementing a unified web portal that enhances the educational experience while maintaining the core security challenges.

## Key Achievements

### 1. CloudAI Labs Web Portal
- **Architecture**: Single Cloud Function serving Flask application
- **URL Structure**: `https://[region]-[project].cloudfunctions.net/cloudai-portal/`
- **Public Access**: All users can access without authentication
- **Integration**: Seamlessly connects all 4 modules through web interface

### 2. Module-Specific Web Entry Points

#### Module 1: API Documentation (`/docs`)
- Displays code examples with bucket names
- Lists available models (dev/prod separation)
- API endpoints reveal sensitive information
- **Attack Vector**: Students discover bucket names → explore with gsutil

#### Module 2: System Status (`/status`)
- Shows "recent deployments" with terraform state locations
- Displays deployment artifacts in production bucket
- **Attack Vector**: Students find state file URL → download → extract SSH key

#### Module 3: Monitoring Dashboard (`/monitoring`)
- Web form interface for monitoring function
- Dropdown to select metadata parameters
- Real-time display of function responses
- **Attack Vector**: Students use web UI for SSRF → extract access token visually

#### Module 4: Admin Console (`/admin`)
- Requires authentication (token from Module 3)
- Visual display of service accounts and IAM roles
- Permission testing interface
- **Attack Vector**: Students visualize IAM relationships → understand privilege escalation

### 3. Technical Implementation

#### Flask Application Structure
```
terraform/cloudai-portal/
├── main.py                 # Core Flask app with all routes
├── requirements.txt        # Minimal dependencies (Flask, requests, google-auth)
├── templates/             
│   ├── base.html          # Shared layout with CloudAI branding
│   ├── index.html         # Homepage with feature highlights
│   ├── 1-model-downloads.html          # Model Downloads (Module 1)
│   ├── 2-system-status.html        # Deployment status (Module 2)
│   ├── 3-monitoring.html    # Monitoring form (Module 3)
│   └── 4-admin_login.html   # Auth required page # TODO clarify vs below
│   ├── admin.html         # IAM console (Module 4) # TODO clarify vs above 
└── static/
    └── style.css          # Professional styling
```

#### Terraform Configuration
- **File**: `terraform/cloudai-portal.tf`
- **Resources**: Cloud Function with public invoker access
- **Environment Variables**: API keys, monitoring function URL
- **Service Account**: Uses compute default (intentionally over-privileged)

### 4. Infrastructure Modifications

#### Setup Scripts Updated
- **mod1-setup.sh**: Adds portal URL to dev bucket as `portal_info.txt`
- **mod2-setup.sh**: Uploads monitoring UI info to VM for student discovery
- **challenge-setup.sh**: Displays portal URL prominently at completion

#### Minimal Module Changes
- No changes to core terraform infrastructure
- No changes to existing attack paths
- Portal complements but doesn't replace terminal-based challenges

### 5. Educational Enhancements

#### Progressive Discovery
1. Start with dev bucket → Find portal URL
2. Explore portal → Discover prod bucket via status page
3. Use monitoring UI → Extract token visually
4. Access admin console → Understand IAM relationships

#### Multiple Learning Paths
- **Visual Learners**: Use web UI to understand infrastructure
- **Hands-On Learners**: Continue using terminal for exploitation
- **Hybrid Approach**: Discover via web, exploit via terminal

### 6. Security Vulnerabilities (Intentional)

#### API Layer
- Hardcoded API keys in environment variables
- No authentication on public endpoints
- Verbose error messages reveal system details

#### Web Interface
- CORS misconfiguration (allows any origin)
- Token reflection in admin console
- Direct metadata service proxy via monitoring

#### Infrastructure
- Overly permissive service account
- Public access to sensitive endpoints
- No rate limiting or access controls

### 7. Implementation Insights

#### Design Decisions
- **Single Function**: Easier deployment, consistent URL structure
- **Static Branding**: Professional appearance increases engagement
- **Form-Based SSRF**: More intuitive than command-line for beginners
- **Visual IAM**: Complex permissions easier to understand visually

#### Technical Challenges Solved
- Cloud Function routing for Flask app
- Service-to-service authentication for monitoring
- Output formatting for better readability
- Token highlighting in responses

### 8. Future Scaling Considerations

#### For Replication
1. Deploy terraform in correct order (modules 1-2, then main terraform)
2. Run setup scripts sequentially (mod1, mod2, challenge-setup)
3. Verify portal URL appears in terraform output
4. Test each module's web entry point

#### For Enhancement
- Add more "realistic" features (model upload, training status)
- Implement fake authentication system to teach auth bypass
- Create administrative backdoors for additional challenges
- Add logging/monitoring to track student progress

### 9. Success Metrics

#### Completed Deliverables
- ✓ Unified web portal connecting all modules
- ✓ Browser-based entry for each challenge
- ✓ Maintained existing terminal-based flows
- ✓ Enhanced narrative with "CloudAI Labs" branding
- ✓ Zero breaking changes to core infrastructure

#### Educational Value Added
- Visual understanding of cloud infrastructure
- Multiple ways to approach each challenge
- Realistic cloud platform experience
- Clear progression through modules

## Summary
Successfully implemented a comprehensive web portal that transforms a technical CTF into an engaging AI security bootcamp. The portal provides visual, browser-based entry points for each module while preserving the depth of terminal-based exploitation, creating a more accessible and educational experience for students at all skill levels.