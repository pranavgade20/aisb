#!/bin/bash

# mod1-setup.sh - Module 1 specific setup tasks
# Called from challenge-setup.sh after terraform apply

# Check if required parameters are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <PROJECT_ID> <PROJECT_NUMBER>"
    exit 1
fi

PROJECT_ID=$1
PROJECT_NUMBER=$2

echo "##########################################################"
echo "> Setup for module 1."
echo "##########################################################"

# Decode and save the service account key to temporary file
SA_KEY=$(cd terraform_module1 && terraform show -json | jq -r '.values.root_module.resources[] | select(.name=="bucket-sa-key") | .values.private_key' | base64 -d)
echo "$SA_KEY" > temporary_files/bucket-service-account.json

# Upload service account key to dev bucket
gsutil cp temporary_files/bucket-service-account.json gs://modeldata-dev-$PROJECT_ID/

# Create flag1.txt for Module 1 enumeration
echo "flag{found-the-lazy-dev}" > temporary_files/flag1.txt
gsutil cp temporary_files/flag1.txt gs://modeldata-dev-$PROJECT_ID/

# Create some decoy files in dev bucket
echo "Model training logs - nothing sensitive here" > temporary_files/training_logs.txt
echo "Development models - v0.1-alpha" > temporary_files/dev_models.txt
gsutil cp temporary_files/training_logs.txt gs://modeldata-dev-$PROJECT_ID/
gsutil cp temporary_files/dev_models.txt gs://modeldata-dev-$PROJECT_ID/

# Portal URL will be retrieved later after it's actually deployed

# Create portal information file
cat > temporary_files/portal_info.txt << EOF
CloudAI Labs Model Portal
========================

Access our web portal for model management and monitoring:
Portal URL will be available after setup completes

Features:
- API Documentation: /docs
- System Status: /status
- Monitoring Dashboard: /monitoring
- Admin Console: /admin (requires authentication)

For API access, see the documentation page.
EOF

# Upload portal info to dev bucket
gsutil cp temporary_files/portal_info.txt gs://modeldata-dev-$PROJECT_ID/

# Upload intermediate flag to PROD bucket
echo "well-done-what-else-can-you-access" > temporary_files/flag1-partB.txt
gsutil cp temporary_files/flag1-partB.txt gs://modeldata-prod-$PROJECT_ID/

echo "> Module 1 setup complete!"
