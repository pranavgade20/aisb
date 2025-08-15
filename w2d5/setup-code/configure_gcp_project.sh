#!/bin/bash

PROJECT_ID=${TF_VAR_project_id}
echo "Parsed ${PROJECT_ID} from env! Running setup commands..."

sleep 2

gcloud compute disks list 2>/dev/null || gcloud auth login
gcloud config set project "$PROJECT_ID"
gcloud auth application-default login
gcloud auth application-default set-quota-project "$PROJECT_ID"

echo "Enabling required Gcloud API's..."
bash steps_to_enable.sh || exit 1
echo "Project API's enabled! "

STARTYELLOW="\033[1;33m"
ENDYELLOW="\033[0m"
echo -e "${STARTYELLOW} Nice job! Now, run 'bash challenge-setup.sh' to deploy!${ENDYELLOW}"
